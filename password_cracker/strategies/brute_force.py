import itertools
from multiprocessing import Pool, Value
from typing import Optional, Dict, Tuple, List, Callable

from .base_strategy import CrackingStrategy
from ..core.hasher import HashManager
from ..utils.mask_parser import BUILTIN_CHARSETS, parse_mask

DEFAULT_CHARSET = BUILTIN_CHARSETS['a']

_global_found_flag = None


def _init_worker(found_flag):
    global _global_found_flag
    _global_found_flag = found_flag


def _worker_incremental(args: tuple) -> Optional[Tuple[str, str]]:
    global _global_found_flag

    chunk_charset, full_charset, length, target_hash, algorithm, salt, verbose, hex_salt, salt_position = args

    attempts = 0

    for start_char in chunk_charset:
        if _global_found_flag and _global_found_flag.value == 1:
            return None

        if length == 1:
            password = start_char
            attempts += 1

            is_match, found_algorithm = HashManager.verify_hash(
                password, target_hash, algorithm, salt, hex_salt, salt_position
            )

            if is_match:
                return password, found_algorithm
        else:
            for combo in itertools.product(full_charset, repeat=length - 1):
                if _global_found_flag and _global_found_flag.value == 1:
                    return None

                password = start_char + ''.join(combo)
                attempts += 1

                is_match, found_algorithm = HashManager.verify_hash(
                    password, target_hash, algorithm, salt, hex_salt, salt_position
                )

                if is_match:
                    return password, found_algorithm

    return None


def _worker_mask(args):
    global _global_found_flag

    chunk_charset, first_var_idx, parsed_mask, target_hash, algorithm, salt, verbose, hex_salt, salt_position = args

    variable_charsets = []
    variable_positions = []

    for idx, (type_, charset) in enumerate(parsed_mask):
        if type_ == 'variable':
            if idx == first_var_idx:
                variable_positions.append(idx)
            else:
                variable_positions.append(idx)
                variable_charsets.append(charset)

    attempts = 0

    for chunk_char in chunk_charset:
        if _global_found_flag and _global_found_flag.value == 1:
            return None

        if variable_charsets:
            for other_combo in itertools.product(*variable_charsets):
                if attempts % 1000 == 0 and _global_found_flag and _global_found_flag.value == 1:
                    return None

                password_chars = []
                other_idx = 0

                for idx, (type_, charset) in enumerate(parsed_mask):
                    if type_ == 'fixed':
                        password_chars.append(charset[0])
                    elif idx == first_var_idx:
                        password_chars.append(chunk_char)
                    else:
                        password_chars.append(other_combo[other_idx])
                        other_idx += 1

                password = ''.join(password_chars)
                attempts += 1

                is_match, found_algorithm = HashManager.verify_hash(
                    password, target_hash, algorithm, salt, hex_salt, salt_position
                )

                if is_match:
                    return password, found_algorithm
        else:
            password_chars = []

            for idx, (type_, charset) in enumerate(parsed_mask):
                if type_ == 'fixed':
                    password_chars.append(charset[0])
                else:
                    password_chars.append(chunk_char)

            password = ''.join(password_chars)
            attempts += 1

            is_match, found_algorithm = HashManager.verify_hash(
                password, target_hash, algorithm, salt, hex_salt, salt_position
            )

            if is_match:
                return password, found_algorithm

    return None


class BruteForceStrategy(CrackingStrategy):
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
            start_length: int = 1,
            progress_callback: Optional[Callable] = None,
            **kwargs
    ) -> Optional[str]:
        mask = kwargs.get('mask')

        if processes == 1:
            if mask:
                return self._mask_mode(
                    target_hash, algorithm, salt, verbose, mask, kwargs,
                    hex_salt, salt_position, progress_callback
                )
            else:
                return self._incremental_mode(
                    target_hash, algorithm, salt, verbose, kwargs,
                    hex_salt, salt_position, start_length, progress_callback
                )

        if mask:
            return self._mask_mode_parallel(
                target_hash, algorithm, salt, verbose, mask, kwargs, processes,
                hex_salt, salt_position, progress_callback
            )
        else:
            return self._incremental_mode_parallel(
                target_hash, algorithm, salt, verbose, kwargs, processes,
                hex_salt, salt_position, start_length, progress_callback
            )

    def _prepare_incremental(
            self,
            kwargs: dict,
            verbose: bool,
            num_processes: int = 1
    ) -> dict:
        min_length = kwargs.get('min_length', 1)
        max_length = kwargs.get('max_length', 8)
        charset_input = kwargs.get('charset', 'a')

        if charset_input in BUILTIN_CHARSETS:
            charset = BUILTIN_CHARSETS[charset_input]
            charset_name = charset_input
        else:
            charset = charset_input
            charset_name = 'custom'

        if verbose:
            mode_str = "incremental mode, multiprocessing" if num_processes > 1 else "incremental mode"
            print(f"[*] Brute force attack ({mode_str})")
            if num_processes > 1:
                print(f"[*] Processes: {num_processes}")
            print(f"[*] Charset: {charset_name} ({len(charset)} characters)")
            print(f"[*] Length range: {min_length}-{max_length}")

            total = sum(len(charset) ** length for length in range(min_length, max_length + 1))
            print(f"[*] Total combinations: {total:,}")

            if max_length > 6 or total > 100_000_000:
                print("[WARNING] This will take a VERY long time!")

        return {
            'min_length': min_length,
            'max_length': max_length,
            'charset': charset,
            'charset_name': charset_name
        }

    def _prepare_mask(
            self,
            mask: str,
            kwargs: dict,
            verbose: bool,
            num_processes: int = 1
    ) -> Tuple[list, dict]:
        custom_charsets = kwargs.get('custom_charsets', {})
        parsed_mask = self._parse_mask(mask, custom_charsets)

        if verbose:
            mode_str = "mask mode, multiprocessing" if num_processes > 1 else "mask mode"
            print(f"[*] Brute force attack ({mode_str})")
            if num_processes > 1:
                print(f"[*] Processes: {num_processes}")
            print(f"[*] Mask: {mask}")
            self._print_mask_info(parsed_mask)

        return parsed_mask, custom_charsets

    def _incremental_mode(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            kwargs: dict,
            hex_salt: bool,
            salt_position: str,
            start_length: int = None,
            progress_callback: Optional[Callable] = None
    ) -> Optional[str]:
        config = self._prepare_incremental(kwargs, verbose)

        min_length = config.get('min_length')
        max_length = config.get('max_length')
        charset = config['charset']
        charset_name = config['charset_name']

        resume_from = start_length if start_length and start_length >= min_length else min_length

        attempts = 0

        for length in range(resume_from, max_length + 1):
            if verbose:
                combinations_at_length = len(charset) ** length
                print(f"\n[*] Trying length {length} ({combinations_at_length:,} combinations)...")

            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                attempts += 1

                if verbose and attempts % 10000 == 0:
                    print(f"[*] Tried {attempts:,} passwords...")

                is_match, found_algorithm = HashManager.verify_hash(
                    password, target_hash, algorithm, salt, hex_salt, salt_position
                )

                if is_match:
                    if verbose:
                        print(f"\n[+] PASSWORD CRACKED after {attempts:,} attempts!")
                        print(f"[+] Password: {password}")
                        print(f"[+] Algorithm: {found_algorithm}")
                    return password

            if progress_callback:
                progress_callback({
                    "mode": "incremental",
                    "current_length": length + 1,
                    "min_length": min_length,
                    "max_length": max_length,
                    "charset": charset_name,
                    "processes": 1
                })

        if verbose:
            print(f"\n[-] Tried all {attempts:,} combinations - no match found")

        return None

    def _incremental_mode_parallel(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            kwargs: dict,
            num_processes: int,
            hex_salt: bool,
            salt_position: str,
            start_length: int = None,
            progress_callback: Optional[Callable] = None
    ) -> Optional[str]:
        config = self._prepare_incremental(kwargs, verbose, num_processes)

        min_length = config['min_length']
        max_length = config['max_length']
        charset = config['charset']
        charset_name = config['charset_name']

        resume_from = start_length if start_length and start_length >= min_length else min_length

        found_flag = Value('i', 0)

        for length in range(resume_from, max_length + 1):
            if verbose:
                combinations_at_length = len(charset) ** length
                print(f"\n[*] Trying length {length} ({combinations_at_length:,} combinations)...")

            chunk_size = max(1, len(charset) // num_processes)
            chunks = []

            for i in range(0, len(charset), chunk_size):
                chunk = charset[i: i + chunk_size]
                chunks.append((chunk, charset, length, target_hash, algorithm, salt, verbose, hex_salt, salt_position))

            try:
                with Pool(processes=num_processes, initializer=_init_worker, initargs=(found_flag,)) as pool:
                    for result in pool.imap_unordered(_worker_incremental, chunks):
                        if result is not None:
                            found_flag.value = 1
                            pool.terminate()
                            pool.join()

                            if verbose:
                                print(f"\n[+] PASSWORD CRACKED!")
                                print(f"[+] Password: {result[0]}")
                                print(f"[+] Algorithm: {result[1]}")

                            return result[0]

            except KeyboardInterrupt:
                if verbose:
                    print("\n[!] Attack interrupted, terminating workers...")
                pool.terminate()
                pool.join()
                raise

            if found_flag.value == 1:
                break

            if progress_callback:
                progress_callback({
                    "mode": "incremental",
                    "current_length": length + 1,
                    "min_length": min_length,
                    "max_length": max_length,
                    "charset": charset_name,
                    "processes": num_processes
                })

        if verbose:
            print(f"\n[-] Tried all combinations - no match found")

        return None

    def _mask_mode(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            mask: str,
            kwargs: dict,
            hex_salt: bool,
            salt_position: str,
            progress_callback: Optional[Callable] = None
    ) -> Optional[str]:
        parsed_mask, custom_charsets = self._prepare_mask(mask, kwargs, verbose)

        if progress_callback:
            progress_callback({
                "mode": "mask",
                "mask": mask,
                "custom_charsets": custom_charsets,
                "processes": 1
            })

        return self._generate_and_test(parsed_mask, target_hash, algorithm, salt, verbose, hex_salt, salt_position)

    def _mask_mode_parallel(
            self,
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            mask: str,
            kwargs: dict,
            num_processes: int,
            hex_salt: bool,
            salt_position: str,
            progress_callback: Optional[Callable] = None
    ) -> Optional[str]:
        parsed_mask, custom_charsets = self._prepare_mask(mask, kwargs, verbose, num_processes)

        if progress_callback:
            progress_callback({
                "mode": "mask",
                "mask": mask,
                "custom_charsets": custom_charsets,
                "processes": num_processes
            })

        first_variable_idx = None
        first_variable_charset = None

        for idx, (type_, charset) in enumerate(parsed_mask):
            if type_ == 'variable':
                first_variable_idx = idx
                first_variable_charset = charset
                break

        if first_variable_idx is None:
            password = ''.join(charset[0] for _, charset in parsed_mask)
            is_match, found_algorithm = HashManager.verify_hash(
                password, target_hash, algorithm, salt, hex_salt, salt_position
            )
            if is_match:
                if verbose:
                    print(f"[+] PASSWORD CRACKED!")
                    print(f"[+] Password: {password}")
                    print(f"[+] Algorithm: {found_algorithm}")
                return password
            return None

        chunk_size = max(1, len(first_variable_charset) // num_processes)
        chunks = []

        for i in range(0, len(first_variable_charset), chunk_size):
            chunk = first_variable_charset[i: i + chunk_size]
            chunks.append((chunk, first_variable_idx, parsed_mask, target_hash, algorithm, salt, verbose, hex_salt,
                           salt_position))

        found_flag = Value('i', 0)

        try:
            with Pool(processes=num_processes, initializer=_init_worker, initargs=(found_flag,)) as pool:
                for result in pool.imap_unordered(_worker_mask, chunks):
                    if result is not None:
                        found_flag.value = 1
                        pool.terminate()
                        pool.join()

                        if verbose:
                            print(f"\n[+] PASSWORD CRACKED!")
                            print(f"[+] Password: {result[0]}")
                            print(f"[+] Algorithm: {result[1]}")

                        return result[0]

        except KeyboardInterrupt:
            if verbose:
                print("\n[!] Attack interrupted, terminating workers...")
            pool.terminate()
            pool.join()
            raise

        if verbose:
            print(f"\n[-] Tried all combinations - no match found")
        return None

    def _parse_mask(self, mask: str, custom_charsets: Dict[str, str]) -> List[Tuple[str, List[str]]]:
        return parse_mask(mask, custom_charsets)

    def _print_mask_info(self, parsed_mask: List[Tuple[str, List[str]]]) -> None:
        variable_count = sum(1 for type_, _ in parsed_mask if type_ == 'variable')
        fixed_count = sum(1 for type_, _ in parsed_mask if type_ == 'fixed')

        total_combinations = 1
        for type_, charset in parsed_mask:
            if type_ == 'variable':
                total_combinations *= len(charset)

        print(f"[*] Pattern length: {len(parsed_mask)} characters")
        print(f"[*] Variable positions: {variable_count}")
        print(f"[*] Fixed positions: {fixed_count}")
        print(f"[*] Total combinations: {total_combinations:,}")

    def _generate_and_test(
            self,
            parsed_mask: List[Tuple[str, List[str]]],
            target_hash: str,
            algorithm: Optional[str],
            salt: str,
            verbose: bool,
            hex_salt: bool,
            salt_position: str
    ) -> Optional[str]:
        positions = []
        charsets_for_product = []

        for idx, (type_, charset) in enumerate(parsed_mask):
            positions.append((idx, type_, charset))
            if type_ == 'variable':
                charsets_for_product.append(charset)

        if not charsets_for_product:
            password = ''.join(charset[0] for _, _, charset in positions)
            is_match, found_algorithm = HashManager.verify_hash(
                password, target_hash, algorithm, salt, hex_salt, salt_position
            )

            if is_match:
                if verbose:
                    print(f"[+] PASSWORD CRACKED!")
                    print(f"[+] Password: {password}")
                    print(f"[+] Algorithm: {found_algorithm}")
                return password
            return None

        attempts = 0

        for combination in itertools.product(*charsets_for_product):
            password_chars = []
            combo_idx = 0

            for idx, type_, charset in positions:
                if type_ == 'fixed':
                    password_chars.append(charset[0])
                else:
                    password_chars.append(combination[combo_idx])
                    combo_idx += 1

            password = ''.join(password_chars)
            attempts += 1

            is_match, found_algorithm = HashManager.verify_hash(
                password, target_hash, algorithm, salt, hex_salt, salt_position
            )

            if is_match:
                if verbose:
                    print(f"\n[+] PASSWORD CRACKED after {attempts:,} attempts!")
                    print(f"[+] Password: {password}")
                    print(f"[+] Algorithm: {found_algorithm}")
                return password

        if verbose:
            print(f"\n[-] Tried all {attempts:,} combinations - no match found")

        return None
