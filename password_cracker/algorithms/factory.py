from .base_hasher import HashAlgorithm
from .md5_hasher import MD5Hasher
from .sha1_hasher import SHA1Hasher
from .sha256_hasher import SHA256Hasher
from .sha3_hasher import SHA3256Hasher
from .sha3_hasher import SHA3512Hasher
from .blake3_hasher import BLAKE3Hasher
from .argon2_hasher import Argon2Hasher
from .ripemd160_hasher import RIPEMD160Hasher


class HashFactory:
    _algorithms = [
        SHA256Hasher(),
        MD5Hasher(),
        SHA1Hasher(),
        BLAKE3Hasher(),
        SHA3256Hasher(),
        SHA3512Hasher(),
        RIPEMD160Hasher(),
        Argon2Hasher()
    ]

    @classmethod
    def get_algorithm_by_name(cls, name: str) -> HashAlgorithm:
        search_name = name.upper().strip()
        for algorithm in cls._algorithms:
            if algorithm.name == search_name:
                return algorithm
        raise ValueError(f"Algorithm with name {name} not found")

    @classmethod
    def get_algorithm_by_length(cls, hash_string: str) -> list[HashAlgorithm]:
        possible_algorithms = []

        for algorithm in cls._algorithms:
            if algorithm.validate_format(hash_string):
                possible_algorithms.append(algorithm)

        return possible_algorithms

    @classmethod
    def get_supported_algorithms(cls) -> list[str]:
        return [algorithm.name for algorithm in cls._algorithms]

    @classmethod
    def get_all_instances(cls) -> list[HashAlgorithm]:
        return cls._algorithms

    @classmethod
    def identify_hash(cls, hash_string: str) -> list[str]:
        matches = cls.get_algorithm_by_length(hash_string)
        return [algorithm.name for algorithm in matches]
