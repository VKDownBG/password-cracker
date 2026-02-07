from Crypto.Hash import RIPEMD160

from .base_hasher import HashAlgorithm


class RIPEMD160Hasher(HashAlgorithm):
    @property
    def name(self) -> str:
        return "RIPEMD160"

    @property
    def hash_length(self) -> int:
        return 40

    def hash(self, text: str | bytes) -> str:
        data = text.encode('utf-8') if isinstance(text, str) else text
        h = RIPEMD160.new(data=data)
        return h.hexdigest()

    def hash_file(self, file_path: str) -> str:
        hasher = RIPEMD160.new()
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
