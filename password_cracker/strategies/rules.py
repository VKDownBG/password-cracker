import os
from multiprocessing import Pool, Value
from typing import Optional, Tuple, List, Union, Callable

from .base_strategy import CrackingStrategy
from ..core.hasher import HashManager
from ..utils.mangling import load_rule_file, count_lines
from ..utils.mangling.rule_engine import apply_rule

_global_found_flag = None


def _init_worker(found_flag):
    global _global_found_flag
    _global_found_flag = found_flag


def _worker_rules(args: tuple) -> Tuple[int, Optional[Tuple[str, str]]]:
    global _global_found_flag

    chunk_id, wordlist_path, start_line, end_line, rules, stack, target_hash, algorithm, salt, verbose, hex_salt, salt_position = args

    try:
        with open(wordlist_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for _ in range(start_line):
                next(f)

            for line_num in range(start_line, end_line):
                if _global_found_flag and _global_found_flag.value == 1:
                    return chunk_id, None

                line = f.readline()
                if not line:
                    break

                word = line.strip()
                if not word:
                    continue

                candidates = []

                if stack:
                    current_word = word
                    valid = True
                    for rule in rules:
                        try:
                            current_word = apply_rule(current_word, rule)
                        except ValueError:
                            valid = False
                            break
                    if valid:
                        candidates.append(current_word)
                else:
                    for rule in rules:
                        try:
                            candidate = apply_rule(word, rule)
                            candidates.append(candidate)
                        except ValueError:
                            continue

                for candidate in candidates:
                    if _global_found_flag and _global_found_flag.value == 1:
                        return chunk_id, None

                    is_match, found_algorithm = HashManager.verify_hash(
                        candidate, target_hash, algorithm, salt, hex_salt, salt_position
                    )

                    if is_match:
                        return chunk_id, (candidate, found_algorithm)

    except Exception:
        return chunk_id, None

    return chunk_id, None


class RulesStrategy(CrackingStrategy):
    def execute(self,
                target_hash: str,
                algorithm: Optional[str] = None,
                salt: str = "",
                verbose: bool = False,
                *,
                processes: int = 1,
                hex_salt: bool = False,
                salt_position: str = 'after',
                start_line: int = 0,
                progress_callback: Optional[Callable] = None,
                **kwargs
                ) -> Optional[str]:
        if 'wordlist_path' not in kwargs:
            raise ValueError("RulesStrategy requires 'wordlist_path' in kwargs")

        wordlist_path = kwargs["wordlist_path"]

        try:
            if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) < 1024 * 1024:
                processes = 1
        except Exception:
            pass

        rules = self._load_rules(kwargs.get('rules'))
        stack = kwargs.get('stack', False)

        if processes == 1:
            return self._rules_mode(
                target_hash, algorithm, salt, verbose,
                wordlist_path, rules, stack,
                hex_salt, salt_position, start_line, progress_callback
            )
        else:
            return self._rules_mode_parallel(
                target_hash, algorithm, salt, verbose,
                wordlist_path, rules, stack,
                processes, hex_salt, salt_position, start_line, progress_callback
            )

    def _load_rules(self, rules_input: Union[str, List[str], None]) -> List[str]:
        if not rules_input:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            default_rules_path = os.path.join(
                os.path.dirname(current_dir),
                "utils", "mangling", "rules", "default.rule"
            )
            return load_rule_file(default_rules_path)

        if isinstance(rules_input, list):
            combined_rules = []
            for item in rules_input:
                if os.path.exists(item) or os.path.sep in item or '.' in item:
                    combined_rules.extend(load_rule_file(item))
                else:
                    combined_rules.append(item)
            return combined_rules

        if isinstance(rules_input, str):
            if '/' not in rules_input and '\\' not in rules_input and '.' not in rules_input:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                preset_path = os.path.join(
                    os.path.dirname(current_dir),
                    "utils", "mangling", "rules", f"{rules_input}.rule"
                )
                return load_rule_file(preset_path)
            else:
                return load_rule_file(rules_input)

        raise TypeError(f"'rules' must be a filepath or list of rules, got {type(rules_input)}")

    def _rules_mode(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            wordlist_path: str,
            rules: List[str],
            stack: bool,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable],
    ) -> Optional[str]:
        if verbose:
            print("[*] Rules attack (single-threaded)")
            print(f"[*] Wordlist: {wordlist_path}")
            print(f"[*] Rules loaded: {len(rules)}")
            if stack:
                print("[*] Mode: Stacked Rules")

        if not os.path.exists(wordlist_path):
            if verbose:
                print(f"[!] Wordlist not found: {wordlist_path}")
            return None

        attempts = 0

        try:
            with open(wordlist_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                for _ in range(start_line):
                    next(f, None)

                for line in f:
                    word = line.strip()
                    if not word:
                        continue

                    candidates = []

                    if stack:
                        current_word = word
                        valid = True
                        for rule in rules:
                            try:
                                current_word = apply_rule(current_word, rule)
                            except ValueError:
                                valid = False
                                break
                        if valid:
                            candidates.append(current_word)
                    else:
                        for rule in rules:
                            try:
                                candidates.append(apply_rule(word, rule))
                            except ValueError:
                                continue

                    for candidate in candidates:
                        attempts += 1

                        is_match, found_algorithm = HashManager.verify_hash(
                            candidate, target_hash, algorithm, salt, hex_salt, salt_position
                        )

                        if is_match:
                            if verbose:
                                print(f"\n[+] PASSWORD CRACKED after {attempts:,} attempts!")
                                print(f"[+] Password: {candidate}")
                                print(f"[+] Algorithm: {found_algorithm}")
                            return candidate

                    if progress_callback and (start_line + attempts) % 100 == 0:
                        progress_callback({
                            "line_number": start_line + attempts // (1 if stack else len(rules)),
                            "wordlist_path": wordlist_path,
                            "processes": 1
                        })

        except Exception as e:
            if verbose:
                print(f"[!] Error reading wordlist: {str(e)}")
            return None

        if verbose:
            print(f"[*] Tried all passwords - no match found")
        return None

    def _rules_mode_parallel(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            wordlist_path: str,
            rules: List[str],
            stack: bool,
            num_processes: int,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable],
    ) -> Optional[str]:
        if verbose:
            print("[*] Rules attack (multiprocessing)")
            print(f"[*] Processes: {num_processes}")
            print(f"[*] Wordlist: {wordlist_path}")
            print(f"[*] Rules loaded: {len(rules)}")

        if not os.path.exists(wordlist_path):
            if verbose:
                print(f"[!] Wordlist not found: {wordlist_path}")
            return None

        try:
            total_lines = count_lines(wordlist_path)
        except Exception as e:
            if verbose:
                print(f"[!] Error reading wordlist: {str(e)}")
            return None

        if total_lines == 0:
            if verbose:
                print("[!] Wordlist is empty")
            return None

        CHUNK_SIZE = 1000

        chunks = []
        chunk_id = 0
        current_line = start_line

        while current_line < total_lines:
            chunk_end = min(current_line + CHUNK_SIZE, total_lines)
            chunks.append((
                chunk_id,
                wordlist_path,
                current_line,
                chunk_end,
                rules,
                stack,
                target_hash,
                algorithm,
                salt,
                hex_salt,
                salt_position
            ))
            current_line = chunk_end
            chunk_id += 1

        found_flag = Value('i', 0)

        finished_chunks = set()
        safe_resume_chunk = 0

        try:
            with Pool(processes=num_processes, initializer=_init_worker, initargs=(found_flag,)) as pool:
                for chunk_id, result in pool.imap_unordered(_worker_rules, chunks):
                    if result is not None:
                        found_flag.value = 1
                        pool.terminate()
                        pool.join()

                        if verbose:
                            print(f"\n[+] PASSWORD CRACKED!")
                            print(f"[+] Password: {result[0]}")
                            print(f"[+] Algorithm: {result[1]}")

                        return result[0]

                    finished_chunks.add(chunk_id)

                    while safe_resume_chunk in finished_chunks:
                        finished_chunks.remove(safe_resume_chunk)
                        safe_resume_chunk += 1

                    if progress_callback:
                        safe_line = start_line + (safe_resume_chunk * CHUNK_SIZE)
                        progress_callback({
                            "line_number": min(safe_line, total_lines),
                            "total_lines": total_lines,
                            "wordlist_path": wordlist_path,
                            "processes": num_processes,
                            "chunk_size": CHUNK_SIZE,
                        })

        except KeyboardInterrupt:
            if verbose:
                print("\n[!] Attack interrupted, terminating workers...")
            pool.terminate()
            pool.join()
            raise

        if verbose:
            print(f"\n[-] Tried all {total_lines:,} passwords - no match found")

        return None
