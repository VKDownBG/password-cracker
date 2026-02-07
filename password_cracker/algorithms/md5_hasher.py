import hashlib

from .base_hasher import HashAlgorithm


class MD5Hasher(HashAlgorithm):
    @property
    def name(self) -> str:
        return "MD5"

    @property
    def hash_length(self) -> int:
        return 32

    def hash(self, text: str | bytes) -> str:
        data = text.encode('utf-8') if isinstance(text, str) else text
        return hashlib.md5(data).hexdigest()

    def hash_file(self, file_path: str) -> str:
        hasher = hashlib.md5()
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
