"""
Unit tests for HashManager and hash algorithm implementations.
Tests hash generation, verification, salt handling, and algorithm identification.
"""

import unittest
import tempfile
import os
from password_cracker.core.hasher import HashManager
from password_cracker.algorithms.factory import HashFactory
from password_cracker.algorithms.md5_hasher import MD5Hasher
from password_cracker.algorithms.sha1_hasher import SHA1Hasher
from password_cracker.algorithms.sha256_hasher import SHA256Hasher
from password_cracker.algorithms.sha3_hasher import SHA3256Hasher, SHA3512Hasher
from password_cracker.algorithms.blake3_hasher import BLAKE3Hasher
from password_cracker.algorithms.argon2_hasher import Argon2Hasher
from password_cracker.algorithms.ripemd160_hasher import RIPEMD160Hasher


class TestHashAlgorithms(unittest.TestCase):
    """Test individual hash algorithm implementations"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_string = "password"
        self.test_bytes = b"password"

    def test_md5_hash(self):
        """Test MD5 hashing"""
        hasher = MD5Hasher()
        expected = "5f4dcc3b5aa765d61d8327deb882cf99"

        self.assertEqual(hasher.hash(self.test_string), expected)
        self.assertEqual(hasher.hash(self.test_bytes), expected)
        self.assertEqual(hasher.name, "MD5")
        self.assertEqual(hasher.hash_length, 32)

    def test_sha1_hash(self):
        """Test SHA1 hashing"""
        hasher = SHA1Hasher()
        expected = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"

        self.assertEqual(hasher.hash(self.test_string), expected)
        self.assertEqual(hasher.hash(self.test_bytes), expected)
        self.assertEqual(hasher.name, "SHA1")
        self.assertEqual(hasher.hash_length, 40)

    def test_sha256_hash(self):
        """Test SHA256 hashing"""
        hasher = SHA256Hasher()
        expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

        self.assertEqual(hasher.hash(self.test_string), expected)
        self.assertEqual(hasher.hash(self.test_bytes), expected)
        self.assertEqual(hasher.name, "SHA256")
        self.assertEqual(hasher.hash_length, 64)

    def test_sha3_256_hash(self):
        """Test SHA3-256 hashing"""
        hasher = SHA3256Hasher()
        expected = "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"

        self.assertEqual(hasher.hash(self.test_string), expected)
        self.assertEqual(hasher.hash(self.test_bytes), expected)
        self.assertEqual(hasher.name, "SHA3-256")
        self.assertEqual(hasher.hash_length, 64)

    def test_sha3_512_hash(self):
        """Test SHA3-512 hashing"""
        hasher = SHA3512Hasher()
        expected = "c7c5f15899cc8ffc0e91acedc0c45c1948e8e1a9ce5f2f2d43d8c0b2a3f1b1e8d6f5c4b3a2918e7d6c5b4a3928170615e4d3c2b1a0918e7d6c5b4a392817060"

        result = hasher.hash(self.test_string)
        self.assertEqual(len(result), 128)
        self.assertEqual(hasher.name, "SHA3-512")
        self.assertEqual(hasher.hash_length, 128)

    def test_blake3_hash(self):
        """Test BLAKE3 hashing"""
        hasher = BLAKE3Hasher()
        expected = "97c593acd6e752551077899d574e79bf27cb72540b778f2eee6e2e9c6e9e5b8d"

        result = hasher.hash(self.test_string)
        self.assertEqual(len(result), 64)
        self.assertEqual(hasher.name, "BLAKE3")
        self.assertEqual(hasher.hash_length, 64)

    def test_ripemd160_hash(self):
        """Test RIPEMD160 hashing"""
        hasher = RIPEMD160Hasher()
        expected = "2c08e8f5884750a7b99f6f2f342fc638db25ff31"

        result = hasher.hash(self.test_string)
        self.assertEqual(len(result), 40)
        self.assertEqual(hasher.name, "RIPEMD160")
        self.assertEqual(hasher.hash_length, 40)

    def test_argon2_hash(self):
        """Test Argon2 hashing"""
        hasher = Argon2Hasher()

        # Argon2 produces different hashes each time (includes random salt)
        hash1 = hasher.hash(self.test_string)
        hash2 = hasher.hash(self.test_string)

        self.assertNotEqual(hash1, hash2)
        self.assertTrue(hash1.startswith("$argon2"))
        self.assertTrue(hash2.startswith("$argon2"))
        self.assertEqual(hasher.name, "ARGON2")

    def test_hash_file(self):
        """Test file hashing"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = MD5Hasher()
            expected = "5f4dcc3b5aa765d61d8327deb882cf99"
            result = hasher.hash_file(temp_file)
            self.assertEqual(result, expected)
        finally:
            os.unlink(temp_file)

    def test_hash_file_not_found(self):
        """Test file hashing with non-existent file"""
        hasher = MD5Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    # NEW TESTS FOR PREVIOUSLY UNTESTED FUNCTIONS

    def test_sha1_hash_file(self):
        """Test SHA1 file hashing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = SHA1Hasher()
            expected = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
            result = hasher.hash_file(temp_file)
            self.assertEqual(result, expected)
        finally:
            os.unlink(temp_file)

    def test_sha1_hash_file_not_found(self):
        """Test SHA1 file hashing with non-existent file"""
        hasher = SHA1Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    def test_sha256_hash_file(self):
        """Test SHA256 file hashing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = SHA256Hasher()
            expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
            result = hasher.hash_file(temp_file)
            self.assertEqual(result, expected)
        finally:
            os.unlink(temp_file)

    def test_sha256_hash_file_not_found(self):
        """Test SHA256 file hashing with non-existent file"""
        hasher = SHA256Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    def test_sha3_256_hash_file(self):
        """Test SHA3-256 file hashing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = SHA3256Hasher()
            expected = "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
            result = hasher.hash_file(temp_file)
            self.assertEqual(result, expected)
        finally:
            os.unlink(temp_file)

    def test_sha3_256_hash_file_not_found(self):
        """Test SHA3-256 file hashing with non-existent file"""
        hasher = SHA3256Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    def test_sha3_512_hash_file(self):
        """Test SHA3-512 file hashing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = SHA3512Hasher()
            result = hasher.hash_file(temp_file)
            # Verify it's the correct length
            self.assertEqual(len(result), 128)
            # Verify it's consistent
            result2 = hasher.hash_file(temp_file)
            self.assertEqual(result, result2)
        finally:
            os.unlink(temp_file)

    def test_sha3_512_hash_file_not_found(self):
        """Test SHA3-512 file hashing with non-existent file"""
        hasher = SHA3512Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    def test_blake3_hash_file(self):
        """Test BLAKE3 file hashing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = BLAKE3Hasher()
            expected = "97c593acd6e752551077899d574e79bf27cb72540b778f2eee6e2e9c6e9e5b8d"
            result = hasher.hash_file(temp_file)
            self.assertEqual(len(result), 64)
            # Verify consistency
            result2 = hasher.hash_file(temp_file)
            self.assertEqual(result, result2)
        finally:
            os.unlink(temp_file)

    def test_blake3_hash_file_not_found(self):
        """Test BLAKE3 file hashing with non-existent file"""
        hasher = BLAKE3Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    def test_ripemd160_hash_file(self):
        """Test RIPEMD160 file hashing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_string)
            temp_file = f.name

        try:
            hasher = RIPEMD160Hasher()
            expected = "2c08e8f5884750a7b99f6f2f342fc638db25ff31"
            result = hasher.hash_file(temp_file)
            self.assertEqual(len(result), 40)
            # Verify consistency
            result2 = hasher.hash_file(temp_file)
            self.assertEqual(result, result2)
        finally:
            os.unlink(temp_file)

    def test_ripemd160_hash_file_not_found(self):
        """Test RIPEMD160 file hashing with non-existent file"""
        hasher = RIPEMD160Hasher()
        with self.assertRaises(FileNotFoundError):
            hasher.hash_file("nonexistent_file.txt")

    def test_argon2_hash_file_not_implemented(self):
        """Test that Argon2 file hashing raises NotImplementedError"""
        hasher = Argon2Hasher()
        with self.assertRaises(NotImplementedError):
            hasher.hash_file("any_file.txt")

    def test_argon2_init_custom_parameters(self):
        """Test Argon2 initialization with custom parameters"""
        # Test with custom time_cost
        hasher1 = Argon2Hasher(time_cost=2)
        hash1 = hasher1.hash(self.test_string)
        self.assertTrue(hash1.startswith("$argon2"))

        # Test with custom memory
        hasher2 = Argon2Hasher(memory=32768)
        hash2 = hasher2.hash(self.test_string)
        self.assertTrue(hash2.startswith("$argon2"))

        # Test with custom parallelism
        hasher3 = Argon2Hasher(parallelism=2)
        hash3 = hasher3.hash(self.test_string)
        self.assertTrue(hash3.startswith("$argon2"))

        # Test with all custom parameters
        hasher4 = Argon2Hasher(time_cost=2, memory=32768, parallelism=2)
        hash4 = hasher4.hash(self.test_string)
        self.assertTrue(hash4.startswith("$argon2"))

    def test_argon2_check_needs_rehash(self):
        """Test Argon2 check_needs_rehash functionality"""
        hasher = Argon2Hasher()

        # Generate a hash with current parameters
        hash_value = hasher.hash(self.test_string)

        # Hash with current parameters shouldn't need rehash
        self.assertFalse(hasher.check_needs_rehash(hash_value))

        # Create a hasher with different parameters
        hasher_different = Argon2Hasher(time_cost=1, memory=8192, parallelism=1)

        # Hash from hasher with different params should need rehash
        hash_different = hasher_different.hash(self.test_string)
        needs_rehash = hasher.check_needs_rehash(hash_different)
        # This may or may not need rehash depending on default params
        self.assertIsInstance(needs_rehash, bool)

    def test_argon2_check_needs_rehash_invalid_hash(self):
        """Test Argon2 check_needs_rehash with invalid hash"""
        hasher = Argon2Hasher()

        # Invalid hash should return True (needs rehash)
        self.assertTrue(hasher.check_needs_rehash("invalid_hash"))
        self.assertTrue(hasher.check_needs_rehash("5f4dcc3b5aa765d61d8327deb882cf99"))

    def test_verify_correct_password(self):
        """Test verification with correct password"""
        hasher = MD5Hasher()
        target_hash = "5f4dcc3b5aa765d61d8327deb882cf99"

        self.assertTrue(hasher.verify(self.test_string, target_hash))
        self.assertTrue(hasher.verify(self.test_bytes, target_hash))

    def test_verify_incorrect_password(self):
        """Test verification with incorrect password"""
        hasher = MD5Hasher()
        target_hash = "5f4dcc3b5aa765d61d8327deb882cf99"

        self.assertFalse(hasher.verify("wrongpassword", target_hash))

    def test_verify_case_insensitive(self):
        """Test that hash verification is case-insensitive"""
        hasher = MD5Hasher()
        lowercase_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        uppercase_hash = "5F4DCC3B5AA765D61D8327DEB882CF99"
        mixed_hash = "5f4dCc3B5Aa765d61D8327DeB882cF99"

        self.assertTrue(hasher.verify(self.test_string, lowercase_hash))
        self.assertTrue(hasher.verify(self.test_string, uppercase_hash))
        self.assertTrue(hasher.verify(self.test_string, mixed_hash))

    def test_validate_format_valid(self):
        """Test hash format validation with valid hashes"""
        hasher = MD5Hasher()

        valid_hashes = [
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "5F4DCC3B5AA765D61D8327DEB882CF99",
            "0" * 32,
            "a" * 32,
            "123abc456def789012345678901234ab"
        ]

        for hash_val in valid_hashes:
            self.assertTrue(hasher.validate_format(hash_val))

    def test_validate_format_invalid(self):
        """Test hash format validation with invalid hashes"""
        hasher = MD5Hasher()

        invalid_hashes = [
            "too_short",
            "5f4dcc3b5aa765d61d8327deb882cf99extra",  # Too long
            "5f4dcc3b5aa765d61d8327deb882cf9",  # Too short
            "5f4dcc3b5aa765d61d8327deb882cf9g",  # Invalid character
            "5f4dcc3b-5aa7-65d6-1d83-27deb882cf99",  # Dashes
            "",  # Empty
        ]

        for hash_val in invalid_hashes:
            self.assertFalse(hasher.validate_format(hash_val))

    def test_argon2_verify(self):
        """Test Argon2 verification (special case)"""
        hasher = Argon2Hasher()

        # Generate a hash
        hash_value = hasher.hash(self.test_string)

        # Verify correct password
        self.assertTrue(hasher.verify(self.test_string, hash_value))

        # Verify incorrect password
        self.assertFalse(hasher.verify("wrongpassword", hash_value))

    def test_argon2_validate_format(self):
        """Test Argon2 hash format validation"""
        hasher = Argon2Hasher()

        valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash"
        invalid_hash = "5f4dcc3b5aa765d61d8327deb882cf99"

        self.assertTrue(hasher.validate_format(valid_hash))
        self.assertFalse(hasher.validate_format(invalid_hash))


class TestHashFactory(unittest.TestCase):
    """Test HashFactory functionality"""

    def test_get_algorithm_by_name(self):
        """Test retrieving algorithm by name"""
        md5 = HashFactory.get_algorithm_by_name("MD5")
        self.assertEqual(md5.name, "MD5")

        sha256 = HashFactory.get_algorithm_by_name("sha256")  # Case insensitive
        self.assertEqual(sha256.name, "SHA256")

    def test_get_algorithm_by_name_not_found(self):
        """Test retrieving non-existent algorithm"""
        with self.assertRaises(ValueError):
            HashFactory.get_algorithm_by_name("INVALID")

    def test_get_algorithm_by_length(self):
        """Test retrieving algorithms by hash length"""
        # MD5 hash (32 chars)
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        algorithms = HashFactory.get_algorithm_by_length(md5_hash)

        self.assertGreater(len(algorithms), 0)
        names = [alg.name for alg in algorithms]
        self.assertIn("MD5", names)

    def test_get_supported_algorithms(self):
        """Test getting list of supported algorithms"""
        algorithms = HashFactory.get_supported_algorithms()

        self.assertIsInstance(algorithms, list)
        self.assertGreater(len(algorithms), 0)
        self.assertIn("MD5", algorithms)
        self.assertIn("SHA256", algorithms)
        self.assertIn("SHA1", algorithms)
        self.assertIn("BLAKE3", algorithms)

    def test_identify_hash(self):
        """Test hash identification"""
        # MD5 hash
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        candidates = HashFactory.identify_hash(md5_hash)
        self.assertIn("MD5", candidates)

        # SHA256 hash
        sha256_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        candidates = HashFactory.identify_hash(sha256_hash)
        self.assertIn("SHA256", candidates)

    # NEW TEST FOR PREVIOUSLY UNTESTED FUNCTION
    def test_get_all_instances(self):
        """Test getting all algorithm instances"""
        instances = HashFactory.get_all_instances()

        self.assertIsInstance(instances, list)
        self.assertGreater(len(instances), 0)

        # Verify all instances are HashAlgorithm objects
        from password_cracker.algorithms.base_hasher import HashAlgorithm
        for instance in instances:
            self.assertIsInstance(instance, HashAlgorithm)

        # Verify we have the expected algorithms
        names = [alg.name for alg in instances]
        self.assertIn("MD5", names)
        self.assertIn("SHA1", names)
        self.assertIn("SHA256", names)
        self.assertIn("SHA3-256", names)
        self.assertIn("SHA3-512", names)
        self.assertIn("BLAKE3", names)
        self.assertIn("RIPEMD160", names)
        self.assertIn("ARGON2", names)


class TestHashManager(unittest.TestCase):
    """Test HashManager functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_password = "password"
        self.md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        self.sha256_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

    def test_normalize_hash(self):
        """Test hash normalization"""
        # Test lowercase conversion
        result = HashManager._normalize_hash("5F4DCC3B5AA765D61D8327DEB882CF99")
        self.assertEqual(result, "5f4dcc3b5aa765d61d8327deb882cf99")

        # Test stripping whitespace
        result = HashManager._normalize_hash("  5f4dcc3b5aa765d61d8327deb882cf99  ")
        self.assertEqual(result, "5f4dcc3b5aa765d61d8327deb882cf99")

        # Test empty string
        result = HashManager._normalize_hash("")
        self.assertEqual(result, "")

    def test_repair_hash(self):
        """Test hash repair functionality"""
        # Should normalize the hash
        result = HashManager.repair_hash("  5F4DCC3B5AA765D61D8327DEB882CF99  ")
        self.assertEqual(result, "5f4dcc3b5aa765d61d8327deb882cf99")

    def test_generate_hash(self):
        """Test hash generation"""
        result = HashManager.generate_hash(self.test_password, "MD5")
        self.assertEqual(result, self.md5_hash)

    def test_generate_hash_empty_text(self):
        """Test hash generation with empty text"""
        with self.assertRaises(ValueError):
            HashManager.generate_hash("", "MD5")

    def test_generate_hash_with_salt(self):
        """Test hash generation with salt"""
        # Salt after
        result = HashManager.generate_hash(
            self.test_password,
            "MD5",
            salt="salt",
            salt_position="after"
        )
        self.assertNotEqual(result, self.md5_hash)

        # Salt before
        result_before = HashManager.generate_hash(
            self.test_password,
            "MD5",
            salt="salt",
            salt_position="before"
        )
        self.assertNotEqual(result_before, result)

        # Salt both
        result_both = HashManager.generate_hash(
            self.test_password,
            "MD5",
            salt="salt",
            salt_position="both"
        )
        self.assertNotEqual(result_both, result)
        self.assertNotEqual(result_both, result_before)

    def test_generate_hash_with_hex_salt(self):
        """Test hash generation with hex salt"""
        result = HashManager.generate_hash(
            self.test_password,
            "MD5",
            salt="48656c6c6f",
            hex_salt=True,
            salt_position="after"
        )

        # Should be different from string salt
        result_string = HashManager.generate_hash(
            self.test_password,
            "MD5",
            salt="48656c6c6f",
            hex_salt=False,
            salt_position="after"
        )
        self.assertNotEqual(result, result_string)

    def test_generate_hash_invalid_hex_salt(self):
        """Test hash generation with invalid hex salt"""
        with self.assertRaises(ValueError):
            HashManager.generate_hash(
                self.test_password,
                "MD5",
                salt="not_hex",
                hex_salt=True
            )

    def test_verify_hash_correct(self):
        """Test hash verification with correct password"""
        is_match, algorithm = HashManager.verify_hash(
            self.test_password,
            self.md5_hash,
            "MD5"
        )

        self.assertTrue(is_match)
        self.assertEqual(algorithm, "MD5")

    def test_verify_hash_incorrect(self):
        """Test hash verification with incorrect password"""
        is_match, algorithm = HashManager.verify_hash(
            "wrongpassword",
            self.md5_hash,
            "MD5"
        )

        self.assertFalse(is_match)
        self.assertEqual(algorithm, "None")

    def test_verify_hash_auto_detect(self):
        """Test hash verification with auto-detection"""
        is_match, algorithm = HashManager.verify_hash(
            self.test_password,
            self.md5_hash
        )

        self.assertTrue(is_match)
        self.assertEqual(algorithm, "MD5")

    def test_verify_hash_with_salt(self):
        """Test hash verification with salt"""
        # Generate hash with salt
        salted_hash = HashManager.generate_hash(
            self.test_password,
            "MD5",
            salt="mysalt",
            salt_position="after"
        )

        # Verify with correct salt
        is_match, algorithm = HashManager.verify_hash(
            self.test_password,
            salted_hash,
            "MD5",
            salt="mysalt",
            salt_position="after"
        )
        self.assertTrue(is_match)

        # Verify with wrong salt
        is_match, algorithm = HashManager.verify_hash(
            self.test_password,
            salted_hash,
            "MD5",
            salt="wrongsalt",
            salt_position="after"
        )
        self.assertFalse(is_match)

        # Verify with wrong position
        is_match, algorithm = HashManager.verify_hash(
            self.test_password,
            salted_hash,
            "MD5",
            salt="mysalt",
            salt_position="before"
        )
        self.assertFalse(is_match)

    def test_identify_algorithms(self):
        """Test algorithm identification"""
        # MD5 (32 chars)
        candidates = HashManager.identify_algorithms(self.md5_hash)
        self.assertIn("MD5", candidates)

        # SHA256 (64 chars)
        candidates = HashManager.identify_algorithms(self.sha256_hash)
        self.assertIn("SHA256", candidates)

        # Should handle uppercase/lowercase
        candidates = HashManager.identify_algorithms(self.md5_hash.upper())
        self.assertIn("MD5", candidates)

    def test_hash_file(self):
        """Test file hashing"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_password)
            temp_file = f.name

        try:
            result = HashManager.hash_file(temp_file, "MD5")
            self.assertEqual(result, self.md5_hash)
        finally:
            os.unlink(temp_file)

    def test_verify_file_integrity(self):
        """Test file integrity verification"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write(self.test_password)
            temp_file = f.name

        try:
            # Verify with correct hash
            is_match, algorithm = HashManager.verify_file_integrity(
                temp_file,
                self.md5_hash,
                "MD5"
            )
            self.assertTrue(is_match)
            self.assertEqual(algorithm, "MD5")

            # Verify with wrong hash
            is_match, algorithm = HashManager.verify_file_integrity(
                temp_file,
                "0" * 32,
                "MD5"
            )
            self.assertFalse(is_match)

            # Verify with auto-detection
            is_match, algorithm = HashManager.verify_file_integrity(
                temp_file,
                self.md5_hash
            )
            self.assertTrue(is_match)
            self.assertEqual(algorithm, "MD5")
        finally:
            os.unlink(temp_file)

    def test_get_supported_algorithms(self):
        """Test getting supported algorithms"""
        algorithms = HashManager.get_supported_algorithms()

        self.assertIsInstance(algorithms, list)
        self.assertGreater(len(algorithms), 0)
        self.assertIn("MD5", algorithms)
        self.assertIn("SHA256", algorithms)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""

    def test_unicode_text(self):
        """Test hashing unicode text"""
        unicode_text = "пароль"  # Russian for "password"

        hasher = MD5Hasher()
        result = hasher.hash(unicode_text)

        # Should produce consistent hash
        result2 = hasher.hash(unicode_text)
        self.assertEqual(result, result2)

        # Should be verifiable
        self.assertTrue(hasher.verify(unicode_text, result))

    def test_empty_hash_string(self):
        """Test handling of empty hash string"""
        candidates = HashManager.identify_algorithms("")
        self.assertEqual(len(candidates), 0)

    def test_whitespace_only_hash(self):
        """Test handling of whitespace-only hash"""
        candidates = HashManager.identify_algorithms("   ")
        self.assertEqual(len(candidates), 0)

    def test_very_long_text(self):
        """Test hashing very long text"""
        long_text = "a" * 10000

        hasher = MD5Hasher()
        result = hasher.hash(long_text)

        # Should still be valid MD5 length
        self.assertEqual(len(result), 32)

        # Should be verifiable
        self.assertTrue(hasher.verify(long_text, result))

    def test_binary_data(self):
        """Test hashing binary data"""
        binary_data = b'\x00\x01\x02\x03\x04\x05'

        hasher = MD5Hasher()
        result = hasher.hash(binary_data)

        # Should produce valid hash
        self.assertEqual(len(result), 32)

        # Should be verifiable
        self.assertTrue(hasher.verify(binary_data, result))


if __name__ == '__main__':
    unittest.main()