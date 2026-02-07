import hashlib

from .base_hasher import HashAlgorithm


class SHA256Hasher(HashAlgorithm):
    @property
    def name(self) -> str:
        return "SHA256"

    @property
    def hash_length(self) -> int:
        return 64

    def hash(self, text: str | bytes) -> str:
        data = text.encode('utf-8') if isinstance(text, str) else text
        return hashlib.sha256(data).hexdigest()

    def hash_file(self, file_path: str) -> str:
        hasher = hashlib.sha256()
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
