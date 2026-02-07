import hashlib

from .base_hasher import HashAlgorithm


class SHA3256Hasher(HashAlgorithm):
    @property
    def name(self) -> str:
        return "SHA3-256"

    @property
    def hash_length(self) -> int:
        return 64

    def hash(self, text: str | bytes) -> str:
        data = text.encode('utf-8') if isinstance(text, str) else text
        return hashlib.sha3_256(data).hexdigest()

    def hash_file(self, file_path: str) -> str:
        hasher = hashlib.sha3_256()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    hasher.update(data)
        except FileNotFoundError:
            raise FileNotFoundError(f"File {file_path} not found")

        return hasher.hexdigest()


class SHA3512Hasher(HashAlgorithm):
    @property
    def name(self) -> str:
        return "SHA3-512"

    @property
    def hash_length(self) -> int:
        return 128

    def hash(self, text: str | bytes) -> str:
        data = text.encode('utf-8') if isinstance(text, str) else text
        return hashlib.sha3_512(data).hexdigest()

    def hash_file(self, file_path: str) -> str:
        hasher = hashlib.sha3_512()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    hasher.update(data)
        except FileNotFoundError:
            raise FileNotFoundError(f"File {file_path} not found")

        return hasher.hexdigest()
