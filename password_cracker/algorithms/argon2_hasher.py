from argon2 import PasswordHasher, exceptions

from .base_hasher import HashAlgorithm


class Argon2Hasher(HashAlgorithm):
    def __init__(self, time_cost=None, memory=None, parallelism=None):
        options = {}
        if time_cost is not None:
            options["time_cost"] = time_cost
        if memory is not None:
            options["memory_cost"] = memory
        if parallelism is not None:
            options["parallelism"] = parallelism

        self.ph = PasswordHasher(**options)

    @property
    def name(self) -> str:
        return "ARGON2"

    @property
    def hash_length(self) -> int:
        return 0

    def hash(self, text: str | bytes) -> str:
        return self.ph.hash(text)

    def hash_file(self, file_path: str) -> str:
        raise NotImplementedError("Argon2 is not suitable for file hashing.")

    def verify(self, text: str | bytes, hash_value: str) -> bool:
        try:
            return self.ph.verify(hash_value, text)
        except (exceptions.VerificationError, exceptions.InvalidHash, ValueError):
            return False

    def validate_format(self, hash_value: str) -> bool:
        return hash_value.startswith("$argon2")

    def check_needs_rehash(self, hash_value: str) -> bool:
        try:
            return self.ph.check_needs_rehash(hash_value)
        except (exceptions.InvalidHash, ValueError):
            return True
