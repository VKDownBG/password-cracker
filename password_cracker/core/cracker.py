import os.path
import threading
import time
from typing import Optional, Dict, Set
import json
from datetime import datetime

from .hasher import HashManager
from ..strategies import DictionaryStrategy
from ..strategies import RulesStrategy
from ..strategies import BruteForceStrategy
from ..strategies import HybridStrategy
from ..strategies import CombinatorStrategy


class PasswordCracker:
    def __init__(
            self,
            target_hash: str,
            algorithm: str = None,
            salt: str = "",
            hex_salt: bool = False,
            salt_position: str = 'after',
            verbose: bool = False,
            checkpoint_interval: int = 60,
            session_name: str = None
    ):
        self.target_hash = HashManager.repair_hash(target_hash)
        self.algorithm = algorithm
        self.salt = salt
        self.hex_salt = hex_salt
        self.salt_position = salt_position
        self.verbose = verbose
        self.checkpoint_interval = checkpoint_interval

        cache_folder = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        self.cache_path = os.path.join(cache_folder, "cache")
        os.makedirs(self.cache_path, exist_ok=True)

        self.potfile_path = os.path.join(self.cache_path, "cracked.potfile")

        if session_name:
            filename = f"{session_name}.json" if not session_name.endswith('.json') else session_name
        else:
            hash_prefix = self.target_hash[:8]
            algo_name = algorithm if algorithm else "auto"
            filename = f"session_{hash_prefix}_{algo_name}.json"
        self.restore_file = os.path.join(self.cache_path, filename)

        self.pending_resume = None
        self.current_progress = None
        self.checkpoint_thread = None

        self.current_strategy = None
        self.stop_event = threading.Event()

    # CRACKED PASSWORDS POTFILE LOGIC

    def check_potfile(self) -> Optional[str]:
        if not os.path.exists(self.potfile_path):
            return None

        try:
            passwords_to_test = self._load_existing_passwords().copy()

            with open(self.potfile_path, "r", encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue

                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        continue

                    cracked_hash, password = parts

                    if cracked_hash == self.target_hash:
                        if self.verbose:
                            print(f"[+] Hash found in potfile!")
                            print(f"[+] Password: {password}")
                        return password

            if passwords_to_test:
                if self.verbose:
                    print(f"[*] No exact match found, testing {len(passwords_to_test)} known passwords...")

                for password in passwords_to_test:
                    is_match, found_algorithm = HashManager.verify_hash(
                        password, self.target_hash, self.algorithm, self.salt, self.hex_salt, self.salt_position
                    )

                    if is_match:
                        if self.verbose:
                            print(f"[+] Hash cracked after testing {len(passwords_to_test)} known passwords!")
                            print(f"[+] Password: {password}")
                            print(f"[+] Algorithm: {found_algorithm}")
                        return password

        except Exception as e:
            if self.verbose:
                print(f"[!] Error reading potfile: {str(e)}")
            return None

        return None

    def save_to_potfile(self, password: str) -> None:
        try:
            existing_passwords = self._load_existing_passwords()

            if password in existing_passwords:
                if self.verbose:
                    print(f"[*] Password '{password}' already in potfile")
                return

            supported_algorithms = HashManager.get_supported_algorithms()
            RANDOM_SALT_ALGORITHMS = ["Argon2", "bcrypt", "scrypt"]
            new_entries = []

            new_entries.append(f"{self.target_hash}:{password}")

            for algo in supported_algorithms:
                if algo in RANDOM_SALT_ALGORITHMS:
                    continue

                if self.algorithm and algo.lower() == self.algorithm.lower():
                    continue

                try:
                    hashed = HashManager.generate_hash(
                        password,
                        algo,
                        self.salt,
                        self.hex_salt,
                        self.salt_position
                    )
                    new_entries.append(f"{hashed}:{password}")

                except Exception as e:
                    if self.verbose:
                        print(f"[!] Could not generate {algo} hash: {e}")
                    continue

            if new_entries:
                with open(self.potfile_path, "a", encoding='utf-8-sig') as f:
                    for entry in new_entries:
                        f.write(f"{entry}\n")

                if self.verbose:
                    print(f"[+] Saved {len(new_entries)} hash variants to potfile")

            else:
                if self.verbose:
                    print(f"[*] All hash variants already in potfile")

        except Exception as e:
            if self.verbose:
                print(f"[!] Error saving to potfile: {str(e)}")

    def _load_existing_hashes(self) -> Set[str]:
        existing = set()

        if not os.path.exists(self.potfile_path):
            return existing

        try:
            with open(self.potfile_path, "r", encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue

                    hash_value = line.split(":", 1)[0]
                    existing.add(hash_value)

        except Exception as e:
            if self.verbose:
                print(f"[!] Error loading existing hashes: {str(e)}")

        return existing

    def _load_existing_passwords(self) -> Set[str]:
        existing = set()

        if not os.path.exists(self.potfile_path):
            return existing

        try:
            with open(self.potfile_path, "r", encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue

                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        existing.add(parts[1])

        except Exception as e:
            if self.verbose:
                print(f"[!] Error loading existing hashes: {str(e)}")

        return existing

    def _execute_with_cache(self, strategy_name: str, strategy_func, **strategy_kwargs) -> Optional[str]:
        cached_password = self.check_potfile()
        if cached_password:
            return cached_password

        session = self._check_resume(strategy_name)

        if session:
            progress = session.get('progress', {})

            if strategy_name == "brute_force":
                start_length = progress.get("current_length")
                if start_length is not None:
                    strategy_kwargs['min_length'] = start_length
                    if self.verbose:
                        print(f"[*] Resuming from length {start_length}")
                else:
                    if self.verbose:
                        print("[*] Resuming mask attack (restarting strategy)")
            else:
                start_line = progress.get("line_number", 0)
                if start_line > 0:
                    strategy_kwargs['start_line'] = start_line
                    if self.verbose:
                        print(f"[*] Resuming from line {start_line}")

        def on_progress(data):
            self.current_progress = data

        strategy_kwargs['progress_callback'] = on_progress

        self._start_checkpoint_thread(strategy_name)

        try:
            result = strategy_func(**strategy_kwargs)

            if result:
                self.save_to_potfile(result)

            self._stop_checkpoint_thread(clear_session=True)
            return result

        except KeyboardInterrupt:
            if self.current_progress and self.current_strategy:
                if self.verbose:
                    print("[*] Performing emergency save...")
                self._save_session(self.current_strategy, self.current_progress)

            self._stop_checkpoint_thread(clear_session=False)
            if self.verbose:
                print("\n[!] Attack interrupted - progress saved")
            raise

        except Exception as e:
            self._stop_checkpoint_thread(clear_session=False)
            if self.verbose:
                print(f"\n[!] Error during attack: {e}")
            raise

    def show_potfile_stats(self) -> None:
        if not os.path.exists(self.potfile_path):
            print("[*] Potfile does not exist yet")
            return

        try:
            with open(self.potfile_path, "r", encoding='utf-8-sig') as f:
                lines = f.readlines()

            total_entries = len([l for l in lines if l.strip() and ":" in l])
            unique_passwords = len(set(l.split(":", 1)[1].strip() for l in lines if l.strip() and ":" in l))

            print(f"[*] Potfile: {self.potfile_path}")
            print(f"[*] Total hash entries: {total_entries}")
            print(f"[*] Unique passwords: {unique_passwords}")

        except Exception as e:
            print(f"[!] Error reading potfile stats: {e}")

    # PROGRESS LOGIC

    def _load_session(self) -> Optional[dict]:
        if not os.path.exists(self.restore_file):
            return None

        try:
            with open(self.restore_file, "r", encoding='utf-8-sig') as f:
                return json.load(f)

        except json.JSONDecodeError:
            if self.verbose:
                print(f"[!] Session restore file is corrupted!")
            os.remove(self.restore_file)
            return None

        except Exception as e:
            if self.verbose:
                print(f"[!] Error loading session: {str(e)}")
            return None

    def _save_session(self, strategy: str, progress: dict) -> None:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            started_at = self.pending_resume.get("started_at") if self.pending_resume else timestamp

            session_data = {
                "target_hash": self.target_hash,
                "algorithm": self.algorithm,
                "salt": self.salt,
                "hex_salt": self.hex_salt,
                "salt_position": self.salt_position,
                "strategy": strategy,
                "started_at": started_at,
                "last_save": timestamp,
                "progress": progress
            }

            with open(self.restore_file, "w", encoding='utf-8-sig') as f:
                json.dump(session_data, f, indent=4)

        except Exception as e:
            if self.verbose:
                print(f"[!] Error saving session: {str(e)}")

    def _clear_session(self):
        try:
            if os.path.exists(self.restore_file):
                os.remove(self.restore_file)
                if self.verbose:
                    print(f"[!] Cleared session file: {self.restore_file}")

        except Exception as e:
            if self.verbose:
                print(f"[!] Error clearing session: {str(e)}")

    def _session_matches(self, session: dict) -> bool:
        required_keys = ["target_hash", "algorithm", "salt", "hex_salt", "salt_position"]
        if not all(key in session for key in required_keys):
            if self.verbose:
                print("[!] Session file is missing required fields")
            return False

        if session["target_hash"] != self.target_hash:
            return False

        if self.algorithm is not None and session["algorithm"] != self.algorithm:
            return False

        if session["salt"] != self.salt:
            return False
        if session["hex_salt"] != self.hex_salt:
            return False
        if session["salt_position"] != self.salt_position:
            return False

        return True

    def _prompt_resume(self, session: dict) -> bool:
        print("\n[*] Found a saved session for this hash!")
        print(f"    Strategy:   {session['strategy']}")
        print(f"    Started at: {session['started_at']}")
        print(f"    Last saved: {session['last_save']}")

        print(f"    Progress:   {json.dumps(session['progress'], indent=12)}")

        response = input("[?] Resume this session? [y/n]: ").strip().lower()
        return response in ["y", "yes"]

    def _handle_strategy_conflict(self, saved_strategy: str, requested_strategy: str) -> str:
        print("\n[!] Conflict: Found a saved session for this target!")
        print(f"    Saved Strategy:  {saved_strategy}")
        print(f"    Current Request: {requested_strategy}")
        print()

        response = input("[?] Do you want to (O)verwrite the save and start fresh, or (A)bort? [O/a]: ").strip().lower()

        if response in ["o", "overwrite"]:
            return "overwrite"
        elif response in ["a", "abort", ""]:
            return "abort"
        else:
            print("[!] Invalid choice - aborting")
            return "abort"

    def _checkpoint_worker(self) -> None:
        while not self.stop_event.is_set():
            time.sleep(self.checkpoint_interval)

            if self.current_progress is not None:
                self._save_session(self.current_strategy, self.current_progress)

    def _start_checkpoint_thread(self, strategy: str) -> None:
        self.current_strategy = strategy
        self.stop_event.clear()

        self.checkpoint_thread = threading.Thread(
            target=self._checkpoint_worker,
            daemon=True
        )
        self.checkpoint_thread.start()

        if self.verbose:
            print(f"[*] Started checkpoint thread (saving every {self.checkpoint_interval}s)")

    def _stop_checkpoint_thread(self, clear_session: bool = True) -> None:
        if self.checkpoint_thread is not None and self.checkpoint_thread.is_alive():
            self.stop_event.set()
            self.checkpoint_thread.join(timeout=5)

        if clear_session:
            self._clear_session()

    def _check_resume(self, requested_strategy: str) -> Optional[dict]:
        try:
            self.pending_resume = self._load_session()

            if self.pending_resume is None:
                return None

            if not self._session_matches(self.pending_resume):
                if self.verbose:
                    print("[!] Session file doesn't match current target - ignoring it")
                self.pending_resume = None
                return None

            saved_strategy = self.pending_resume.get("strategy")

            if saved_strategy == requested_strategy:
                if self._prompt_resume(self.pending_resume):
                    return self.pending_resume
                else:
                    self.pending_resume = None
                    return None
            else:
                choice = self._handle_strategy_conflict(saved_strategy, requested_strategy)

                if choice == "overwrite":
                    self._clear_session()
                    self.pending_resume = None
                    return None
                else:
                    if self.verbose:
                        print("[*] Attack cancelled by user")
                    return None

        except Exception as e:
            if self.verbose:
                print(f"[!] Error checking resume session: {str(e)}")
            return None

    # CRACKING STRATEGIES

    def dictionary(
            self,
            wordlist_path: str,
            processes: int = 1
    ) -> Optional[str]:
        strategy = DictionaryStrategy()
        return self._execute_with_cache(
            strategy_name="dictionary",
            strategy_func=strategy.execute,
            target_hash=self.target_hash,
            algorithm=self.algorithm,
            salt=self.salt,
            verbose=self.verbose,
            processes=processes,
            hex_salt=self.hex_salt,
            salt_position=self.salt_position,
            wordlist_path=wordlist_path
        )

    def rules(
            self,
            wordlist_path: str,
            rules: list[str] | str,
            stack: bool = False,
            processes: int = 1
    ) -> Optional[str]:
        strategy = RulesStrategy()
        return self._execute_with_cache(
            strategy_name="rules",
            strategy_func=strategy.execute,
            target_hash=self.target_hash,
            algorithm=self.algorithm,
            salt=self.salt,
            verbose=self.verbose,
            processes=processes,
            hex_salt=self.hex_salt,
            salt_position=self.salt_position,
            wordlist_path=wordlist_path,
            rules=rules,
            stack=stack
        )

    def brute_force(
            self,
            mask: Optional[str] = None,
            min_length: int = 1,
            max_length: int = 4,
            charset: str = 'a',
            custom_charsets: Optional[Dict[str, str]] = None,
            processes: int = 1
    ) -> Optional[str]:
        strategy = BruteForceStrategy()
        return self._execute_with_cache(
            strategy_name="brute_force",
            strategy_func=strategy.execute,
            target_hash=self.target_hash,
            algorithm=self.algorithm,
            salt=self.salt,
            verbose=self.verbose,
            processes=processes,
            hex_salt=self.hex_salt,
            salt_position=self.salt_position,
            mask=mask,
            min_length=min_length,
            max_length=max_length,
            charset=charset,
            custom_charsets=custom_charsets or {}
        )

    def hybrid(
            self,
            wordlist_path: str,
            mask: str,
            position: str = 'append',
            custom_charsets: Optional[Dict[str, str]] = None,
            processes: int = 1
    ) -> Optional[str]:
        strategy = HybridStrategy()
        return self._execute_with_cache(
            strategy_name="hybrid",
            strategy_func=strategy.execute,
            target_hash=self.target_hash,
            algorithm=self.algorithm,
            salt=self.salt,
            verbose=self.verbose,
            wordlist_path=wordlist_path,
            mask=mask,
            position=position,
            custom_charsets=custom_charsets or {},
            processes=processes,
            hex_salt=self.hex_salt,
            salt_position=self.salt_position
        )

    def combinator(
            self,
            left_wordlist: str,
            right_wordlist: str,
            processes: int = 1,
    ) -> Optional[str]:
        strategy = CombinatorStrategy()
        return self._execute_with_cache(
            strategy_name="combinator",
            strategy_func=strategy.execute,
            target_hash=self.target_hash,
            algorithm=self.algorithm,
            salt=self.salt,
            verbose=self.verbose,
            processes=processes,
            hex_salt=self.hex_salt,
            salt_position=self.salt_position,
            left_wordlist=left_wordlist,
            right_wordlist=right_wordlist
        )
