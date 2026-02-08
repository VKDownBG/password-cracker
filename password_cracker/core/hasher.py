from typing import List, Tuple
from ..algorithms.factory import HashFactory


class HashManager:
    def __init__(self):
        pass

    @staticmethod
    def _normalize_hash(hash_string: str) -> str:
        if not hash_string:
            return ""
        return hash_string.strip()

    @classmethod
    def repair_hash(cls, hash_string: str) -> str:
        return cls._normalize_hash(hash_string)

    @staticmethod
    def get_supported_algorithms() -> List[str]:
        return HashFactory.get_supported_algorithms()

    @staticmethod
    def _resolve_salt(
            salt: str,
            hex_salt: bool = False
    ) -> bytes | str:
        if hex_salt:
            try:
                return bytes.fromhex(salt)
            except ValueError:
                raise ValueError(f"Invalid hex salt: {salt}")
        return salt

    @classmethod
    def generate_hash(
            cls,
            text: str,
            algorithm_name: str,
            salt: str = "",
            hex_salt: bool = False,
            salt_position: str = 'after'
    ) -> str:
        if not text:
            raise ValueError("Text to hash cannot be empty")

        if hex_salt:
            text_part = text.encode('utf-8')
            salt_part = cls._resolve_salt(salt, hex_salt=True)
        else:
            text_part = text
            salt_part = salt

        if salt_position == 'before':
            payload = salt_part + text_part
        elif salt_position == 'both':
            payload = salt_part + text_part + salt_part
        else:
            payload = text_part + salt_part

        return HashFactory.get_algorithm_by_name(algorithm_name).hash(payload)

    @staticmethod
    def hash_file(file_path: str, algorithm_name: str) -> str:
        return HashFactory.get_algorithm_by_name(algorithm_name).hash_file(file_path)

    @classmethod
    def identify_algorithms(cls, hash_string: str) -> List[str]:
        normalized_hash = cls._normalize_hash(hash_string)

        return HashFactory.identify_hash(normalized_hash)

    @classmethod
    def verify_hash(
            cls,
            text: str,
            target_hash: str,
            algorithm_name: str = None,
            salt: str = "",
            hex_salt: bool = False,
            salt_position: str = 'after'
    ) -> Tuple[bool, str]:
        target_hash = cls._normalize_hash(target_hash)

        if hex_salt:
            text_part = text.encode('utf-8')
            salt_part = cls._resolve_salt(salt, hex_salt=True)
        else:
            text_part = text
            salt_part = salt

        if salt_position == 'before':
            payload = salt_part + text_part
        elif salt_position == 'both':
            payload = salt_part + text_part + salt_part
        else:
            payload = text_part + salt_part

        algorithms_to_check = []
        if algorithm_name:
            algorithms_to_check = [HashFactory.get_algorithm_by_name(algorithm_name)]
        else:
            algorithms_to_check = HashFactory.get_algorithm_by_length(target_hash)

        for algorithm in algorithms_to_check:
            if algorithm.verify(payload, target_hash):
                return True, algorithm.name

        return False, "None"

    @classmethod
    def verify_file_integrity(
            cls,
            file_path: str,
            target_hash: str,
            algorithm_name: str = None
    ) -> Tuple[bool, str]:
        target_hash = cls._normalize_hash(target_hash)

        algorithms_to_check = []

        if algorithm_name:
            algorithms_to_check = [HashFactory.get_algorithm_by_name(algorithm_name)]
        else:
            algorithms_to_check = HashFactory.get_algorithm_by_length(target_hash)

        for algorithm in algorithms_to_check:
            try:
                calculated_hash = algorithm.hash_file(file_path)

                if calculated_hash.lower() == target_hash:
                    return True, algorithm.name
            except Exception:
                continue

        return False, "None"
