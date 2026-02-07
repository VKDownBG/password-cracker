import os
import itertools
from multiprocessing import Pool, Value
from typing import Optional, Tuple, List, Callable

from .base_strategy import CrackingStrategy
from ..core.hasher import HashManager
from ..utils.mangling.wordlist import read_wordlist, count_lines
from ..utils.mask_parser import parse_mask

_global_found_flag = None


def _init_worker(found_flag):
    global _global_found_flag
    _global_found_flag = found_flag


def _worker_hybrid(args: tuple) -> Tuple[int, Optional[Tuple[str, str]]]:
    global _global_found_flag

    chunk_id, wordlist_path, start_line, end_line, position, target_hash, algorithm, salt, hex_salt, salt_position, parsed_mask = args

    variable_charsets = [charset for type_, charset in parsed_mask if type_ == 'variable']

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

                result = _test_word_with_mask(
                    word, parsed_mask, variable_charsets, position,
                    target_hash, algorithm, salt, hex_salt, salt_position
                )

                if result:
                    return chunk_id, result

    except Exception:
        return chunk_id, None

    return chunk_id, None


def _test_word_with_mask(
        word: str,
        parsed_mask: List[Tuple[str, List[str]]],
        variable_charsets: List[List[str]],
        position: str,
        target_hash: str,
        algorithm: Optional[str],
        salt: str,
        hex_salt: bool,
        salt_position: str
) -> Optional[Tuple[str, str]]:
    if not variable_charsets:
        mask_str = ''.join(charset[0] for _, charset in parsed_mask)
        candidates = [_build_candidate(word, mask_str, position)]
    else:
        candidates = []
        for combo in itertools.product(*variable_charsets):
            mask_chars = []
            combo_idx = 0

            for type_, charset in parsed_mask:
                if type_ == 'fixed':
                    mask_chars.append(charset[0])
                else:
                    mask_chars.append(combo[combo_idx])
                    combo_idx += 1

            mask_str = ''.join(mask_chars)
            candidates.append(_build_candidate(word, mask_str, position))

    for candidate in candidates:
        is_match, found_algorithm = HashManager.verify_hash(
            candidate, target_hash, algorithm, salt, hex_salt, salt_position
        )

        if is_match:
            return candidate, found_algorithm

    return None


def _build_candidate(word: str, mask_str: str, position: str) -> str:
    if position == 'append':
        return word + mask_str
    elif position == 'prepend':
        return mask_str + word
    else:
        raise ValueError(f"Invalid position: {position}")


class HybridStrategy(CrackingStrategy):
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
        if 'wordlist_path' not in kwargs:
            raise ValueError("HybridStrategy requires 'wordlist_path' in kwargs")
        if 'mask' not in kwargs:
            raise ValueError("HybridStrategy requires 'mask' in kwargs")

        wordlist_path = kwargs["wordlist_path"]

        try:
            if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) < 1024 * 1024:
                processes = 1
        except Exception:
            pass

        mask = kwargs["mask"]
        position = kwargs.get('position', 'append')
        custom_charsets = kwargs.get('custom_charsets', {})

        if position not in ['append', 'prepend']:
            raise ValueError(f"Invalid position: {position}")

        parsed_mask = parse_mask(mask, custom_charsets)

        if processes == 1:
            return self._hybrid_mode(
                target_hash, algorithm, salt, verbose,
                wordlist_path, mask, position, parsed_mask,
                hex_salt, salt_position, start_line, progress_callback
            )
        else:
            return self._hybrid_mode_parallel(
                target_hash, algorithm, salt, verbose,
                wordlist_path, mask, position, parsed_mask, processes,
                hex_salt, salt_position, start_line, progress_callback
            )

    def _hybrid_mode(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            wordlist_path: str,
            mask: str,
            position: str,
            parsed_mask: List[Tuple[str, List[str]]],
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable] = None
    ) -> Optional[str]:
        if verbose:
            print("[*] Hybrid attack (single-threaded)")
            print(f"[*] Wordlist: {wordlist_path}")
            print(f"[*] Mask: {mask}")
            print(f"[*] Position: {position}")
            self._print_mask_info(parsed_mask)

        if not os.path.exists(wordlist_path):
            if verbose:
                print(f"[!] Wordlist not found: {wordlist_path}")
            return None

        variable_charsets = [charset for type_, charset in parsed_mask if type_ == 'variable']

        words_tested = 0

        try:
            for word in read_wordlist(wordlist_path, start_line):
                words_tested += 1

                result = _test_word_with_mask(
                    word, parsed_mask, variable_charsets, position,
                    target_hash, algorithm, salt, hex_salt, salt_position
                )

                if result:
                    if verbose:
                        print(f"\n[+] PASSWORD CRACKED after {words_tested:,} words!")
                        print(f"[+] Password: {result[0]}")
                        print(f"[+] Algorithm: {result[1]}")
                    return result[0]

                if progress_callback and words_tested % 1000 == 0:
                    progress_callback({
                        "line_number": start_line + words_tested,
                        "wordlist_path": wordlist_path,
                        "mask": mask,
                        "position": position,
                        "processes": 1
                    })

        except Exception as e:
            if verbose:
                print(f"[!] Error: {e}")
            return None

        if verbose:
            print(f"\n[-] Tested {words_tested} words - no match found")

        return None

    def _hybrid_mode_parallel(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            wordlist_path: str,
            mask: str,
            position: str,
            parsed_mask: List[Tuple[str, List[str]]],
            num_processes: int,
            hex_salt: bool,
            salt_position: str,
            start_line: int,
            progress_callback: Optional[Callable]
    ) -> Optional[str]:
        if verbose:
            print("[*] Hybrid attack (multiprocessing)")
            print(f"[*] Processes: {num_processes}")
            print(f"[*] Wordlist: {wordlist_path}")
            print(f"[*] Mask: {mask}")
            print(f"[*] Position: {position}")
            self._print_mask_info(parsed_mask)

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

        if verbose:
            print(f"[*] Wordlist contains {total_lines:,} words")

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
                position,
                target_hash,
                algorithm,
                salt,
                hex_salt,
                salt_position,
                parsed_mask
            ))
            current_line = chunk_end
            chunk_id += 1

        found_flag = Value('i', 0)

        finished_chunks = set()
        safe_resume_chunk = 0

        try:
            with Pool(processes=num_processes, initializer=_init_worker, initargs=(found_flag,)) as pool:
                for chunk_id, result in pool.imap_unordered(_worker_hybrid, chunks):
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
                            "mask": mask,
                            "position": position,
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
            print(f"\n[-] Tried all {total_lines:,} words - no match found")

        return None

    def _print_mask_info(self, parsed_mask: List[Tuple[str, List[str]]]) -> None:
        variable_count = sum(1 for type_, _ in parsed_mask if type_ == 'variable')
        fixed_count = sum(1 for type_, _ in parsed_mask if type_ == 'fixed')

        combinations = 1
        for type_, charset in parsed_mask:
            if type_ == 'variable':
                combinations *= len(charset)

        print(f"[*] Mask length: {len(parsed_mask)} characters")
        print(f"[*] Variable positions: {variable_count}")
        print(f"[*] Fixed positions: {fixed_count}")
        print(f"[*] Combinations per word: {combinations:,}")
