import blake3

from .base_hasher import HashAlgorithm


class BLAKE3Hasher(HashAlgorithm):
    @property
    def name(self) -> str:
        return "BLAKE3"

    @property
    def hash_length(self) -> int:
        return 64

    def hash(self, text: str | bytes) -> str:
        data = text.encode('utf-8') if isinstance(text, str) else text
        return blake3.blake3(data).hexdigest()

    def hash_file(self, file_path: str) -> str:
        hasher = blake3.blake3()
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
