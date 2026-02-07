import os
from multiprocessing import Pool, Value
from typing import Optional, Tuple, Callable

from .base_strategy import CrackingStrategy
from ..core.hasher import HashManager
from ..utils.mangling import read_wordlist, count_lines

_global_found_flag = None


def _init_worker(found_flag):
    global _global_found_flag
    _global_found_flag = found_flag


def _worker_combinator(args: tuple) -> Tuple[int, Optional[Tuple[str, str]]]:
    global _global_found_flag

    chunk_id, left_path, start_line, end_line, right_path, target_hash, algorithm, salt, hex_salt, salt_position = args

    try:
        right_words = []
        with open(right_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word:
                    right_words.append(word)

        if not right_words:
            return chunk_id, None

        with open(left_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for _ in range(start_line):
                next(f)

            for line_num in range(start_line, end_line):
                if _global_found_flag and _global_found_flag.value == 1:
                    return chunk_id, None

                line = f.readline()
                if not line:
                    break

                left_word = line.strip()
                if not left_word:
                    continue

                for right_word in right_words:
                    if _global_found_flag and _global_found_flag.value == 1:
                        return chunk_id, None

                    candidate = left_word + right_word

                    is_match, found_algorithm = HashManager.verify_hash(
                        candidate, target_hash, algorithm, salt, hex_salt, salt_position
                    )

                    if is_match:
                        return chunk_id, (candidate, found_algorithm)

    except Exception:
        return chunk_id, None

    return chunk_id, None


class CombinatorStrategy(CrackingStrategy):
    def execute(
            self,
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
        if 'left_wordlist' not in kwargs:
            raise ValueError("[!] Missing 'left_wordlist' parameter (required for combinator attack)")
        if 'right_wordlist' not in kwargs:
            raise ValueError("[!] Missing 'right_wordlist' parameter (required for combinator attack)")

        left_path = kwargs['left_wordlist']
        right_path = kwargs['right_wordlist']

        try:
            if os.path.exists(left_path) and os.path.getsize(left_path) < 1024 * 1024:
                processes = 1
        except Exception:
            pass

        if processes == 1:
            return self._combinator_mode(
                target_hash, algorithm, salt, verbose,
                left_path, right_path,
                hex_salt, salt_position, start_line, progress_callback
            )
        else:
            return self._combinator_mode_parallel(
                target_hash, algorithm, salt, verbose,
                left_path, right_path,
                processes, hex_salt, salt_position, start_line, progress_callback
            )

    def _combinator_mode(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            left_path: str,
            right_path: str,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable]
    ) -> Optional[str]:
        if verbose:
            print("[*] Combinator attack (single-threaded)")
            print(f"[*] Left wordlist: {left_path}")
            print(f"[*] Right wordlist: {right_path}")

        try:
            right_words = read_wordlist(right_path)
        except FileNotFoundError:
            if verbose:
                print(f"[!] Right wordlist not found: {right_path}")
            return None
        except Exception as e:
            if verbose:
                print(f"[!] Error reading right wordlist: {str(e)}")
            return None

        if not right_words:
            if verbose:
                print(f"[!] Right wordlist is empty")
            return None

        attempts = 0
        left_words_tested = 0

        try:
            for left_word in read_wordlist(left_path, start_line):
                left_words_tested += 1

                for right_word in right_words:
                    candidate = left_word + right_word
                    attempts += 1

                    is_match, found_algorithm = HashManager.verify_hash(
                        candidate, target_hash, algorithm, salt, hex_salt, salt_position
                    )

                    if is_match:
                        if verbose:
                            print(f"\n[+] PASSWORD CRACKED after {attempts:,} attempts!")
                            print(f"[+] Password: {candidate}")
                            print(f"[+] Left word: {left_word}")
                            print(f"[+] Right word: {right_word}")
                            print(f"[+] Algorithm: {found_algorithm}")
                        return candidate

                if progress_callback and left_words_tested % 100 == 0:
                    progress_callback({
                        "line_number": start_line + left_words_tested,
                        "left_wordlist": left_path,
                        "right_wordlist": right_path,
                        "processes": 1
                    })

        except FileNotFoundError:
            if verbose:
                print(f"[!] Left wordlist not found: {left_path}")
            return None
        except Exception as e:
            if verbose:
                print(f"[!] Error during combinator attack: {e}")
            return None

        if verbose:
            print(
                f"\n[-] Tried {attempts:,} combinations ({left_words_tested:,} left words × {len(right_words):,} right words)")
            print(f"[-] No match found")

        return None

    def _combinator_mode_parallel(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            left_path: str,
            right_path: str,
            num_processes: int,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable]
    ) -> Optional[str]:
        if verbose:
            print("[*] Combinator attack (multiprocessing)")
            print(f"[*] Processes: {num_processes}")
            print(f"[*] Left wordlist: {left_path}")
            print(f"[*] Right wordlist: {right_path}")

        if not os.path.exists(left_path):
            if verbose:
                print(f"[!] Left wordlist not found: {left_path}")
            return None

        if not os.path.exists(right_path):
            if verbose:
                print(f"[!] Right wordlist not found: {right_path}")
            return None

        try:
            total_left_lines = count_lines(left_path)
        except Exception as e:
            if verbose:
                print(f"[!] Error reading left wordlist: {e}")
            return None

        if total_left_lines == 0:
            if verbose:
                print("[!] Left wordlist is empty")
            return None

        try:
            total_right_lines = count_lines(right_path)
        except Exception:
            total_right_lines = 0

        if verbose:
            print(f"[*] Left wordlist: {total_left_lines:,} words")
            if total_right_lines > 0:
                print(f"[*] Right wordlist: {total_right_lines:,} words")
                print(f"[*] Total combinations: {total_left_lines * total_right_lines:,}")

        CHUNK_SIZE = 1000

        chunks = []
        chunk_id = 0
        current_line = start_line

        while current_line < total_left_lines:
            chunk_end = min(current_line + CHUNK_SIZE, total_left_lines)
            chunks.append((
                chunk_id,
                left_path,
                current_line,
                chunk_end,
                right_path,
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
                for chunk_id, result in pool.imap_unordered(_worker_combinator, chunks):
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
                            "line_number": min(safe_line, total_left_lines),
                            "total_lines": total_left_lines,
                            "left_wordlist": left_path,
                            "right_wordlist": right_path,
                            "processes": num_processes,
                            "chunk_size": CHUNK_SIZE
                        })

        except KeyboardInterrupt:
            if verbose:
                print("\n[!] Attack interrupted, terminating workers...")
            pool.terminate()
            pool.join()
            raise

        if verbose:
            if total_right_lines > 0:
                print(f"\n[-] Tried all {total_left_lines * total_right_lines:,} combinations")
            else:
                print(f"\n[-] Tried all combinations")
            print(f"[-] No match found")

        return None
