import re
import secrets
from abc import ABC, abstractmethod


class HashAlgorithm(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def hash_length(self) -> int:
        pass

    @abstractmethod
    def hash(self, text: str | bytes) -> str:
        pass

    @abstractmethod
    def hash_file(self, file_path: str) -> str:
        pass

    def verify(self, text: str | bytes, hash_value: str) -> bool:
        generated_hash = self.hash(text)

        return secrets.compare_digest(generated_hash.lower(), hash_value.lower())

    def validate_format(self, hash_value: str) -> bool:
        if 0 < self.hash_length != len(hash_value):
            return False

        return bool(re.fullmatch(r'^[0-9a-fA-F]+$', hash_value))
