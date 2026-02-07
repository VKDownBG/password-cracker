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


def _worker_dictionary(args: tuple) -> Tuple[int, Optional[Tuple[str, str]]]:
    global _global_found_flag

    chunk_id, wordlist_path, start_line, end_line, target_hash, algorithm, salt, hex_salt, salt_position = args

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

                password = line.strip()
                if not password:
                    continue

                is_match, found_algorithm = HashManager.verify_hash(
                    password, target_hash, algorithm, salt, hex_salt, salt_position
                )

                if is_match:
                    return chunk_id, (password, found_algorithm)

    except Exception:
        return chunk_id, None

    return chunk_id, None


class DictionaryStrategy(CrackingStrategy):
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
            raise ValueError("[!] Missing wordlist path parameter (required for a dictionary attack)")

        wordlist_path = kwargs["wordlist_path"]

        try:
            if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) < 1024 * 1024:
                processes = 1
        except Exception:
            pass

        if processes == 1:
            return self._dictionary_mode(
                target_hash, algorithm, salt, verbose,
                wordlist_path,
                hex_salt, salt_position, start_line, progress_callback
            )
        else:
            return self._dictionary_mode_parallel(
                target_hash, algorithm, salt, verbose,
                wordlist_path,
                processes, hex_salt, salt_position, start_line, progress_callback
            )

    def _dictionary_mode(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            wordlist_path: str,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable],
    ) -> Optional[str]:
        if verbose:
            print("[*] Dictionary attack (single-threaded)")
            print(f"[*] Wordlist: {wordlist_path}")

        if not os.path.exists(wordlist_path):
            if verbose:
                print(f"[!] Wordlist not found: {wordlist_path}")
            return None

        attempts = 0

        try:
            for password in read_wordlist(wordlist_path, start_line):
                attempts += 1

                if progress_callback and attempts % 1000 == 0:
                    progress_callback({
                        "line_number": start_line + attempts,
                        "wordlist_path": wordlist_path,
                        "processes": 1
                    })

                if verbose and attempts % 10000 == 0:
                    print(f"[*] Tried {attempts} passwords...")

                is_match, found_algorithm = HashManager.verify_hash(
                    password, target_hash, algorithm, salt, hex_salt, salt_position
                )

                if is_match:
                    if verbose:
                        print(f"\n[+] PASSWORD CRACKED after {attempts:,} attempts!")
                        print(f"[+] Password: {password}")
                        print(f"[+] Algorithm: {found_algorithm}")
                    return password

        except Exception as e:
            if verbose:
                print(f"[!] Error reading wordlist: {str(e)}")
            return None

        if verbose:
            print(f"[*] Tried all {attempts} passwords - no match found")

        return None

    def _dictionary_mode_parallel(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            wordlist_path: str,
            num_processes: int,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable],
    ) -> Optional[str]:
        if verbose:
            print("[*] Dictionary attack (multiprocessing)")
            print(f"[*] Processes: {num_processes}")
            print(f"[*] Wordlist: {wordlist_path}")

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

        if verbose:
            print(f"[*] Wordlist contains {total_lines:,} lines")

        if total_lines == 0:
            if verbose:
                print(f"[!] Wordlist is empty")
            return None

        CHUNK_SIZE = 50000

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
                target_hash,
                algorithm,
                salt,
                hex_salt,
                salt_position,
            ))
            current_line = chunk_end
            chunk_id += 1

        found_flag = Value('i', 0)

        finished_chunks = set()
        safe_resume_chunk = 0

        try:
            with Pool(processes=num_processes, initializer=_init_worker, initargs=(found_flag,)) as pool:
                for chunk_id, result in pool.imap_unordered(_worker_dictionary, chunks):
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
