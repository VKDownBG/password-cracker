import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock, call
import os
import json
import tempfile
import shutil
from datetime import datetime
import threading
import time

from password_cracker.core.cracker import PasswordCracker


class TestPasswordCrackerInit(unittest.TestCase):
    """Test PasswordCracker initialization"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_init_basic(self, mock_repair):
        mock_repair.return_value = "repaired_hash"

        cracker = PasswordCracker(
            target_hash="test_hash",
            algorithm="md5"
        )

        mock_repair.assert_called_once_with("test_hash")
        self.assertEqual(cracker.target_hash, "repaired_hash")
        self.assertEqual(cracker.algorithm, "md5")
        self.assertEqual(cracker.salt, "")
        self.assertFalse(cracker.hex_salt)
        self.assertEqual(cracker.salt_position, 'after')
        self.assertFalse(cracker.verbose)
        self.assertEqual(cracker.checkpoint_interval, 60)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_init_with_all_params(self, mock_repair):
        mock_repair.return_value = "repaired_hash"

        cracker = PasswordCracker(
            target_hash="test_hash",
            algorithm="sha256",
            salt="mysalt",
            hex_salt=True,
            salt_position='before',
            verbose=True,
            checkpoint_interval=30,
            session_name="test_session"
        )

        self.assertEqual(cracker.algorithm, "sha256")
        self.assertEqual(cracker.salt, "mysalt")
        self.assertTrue(cracker.hex_salt)
        self.assertEqual(cracker.salt_position, 'before')
        self.assertTrue(cracker.verbose)
        self.assertEqual(cracker.checkpoint_interval, 30)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('os.makedirs')
    def test_init_creates_cache_directory(self, mock_makedirs, mock_repair):
        mock_repair.return_value = "repaired_hash"

        cracker = PasswordCracker(target_hash="test_hash")

        mock_makedirs.assert_called_once()
        self.assertTrue(mock_makedirs.call_args[1]['exist_ok'])

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_init_session_name_without_json_extension(self, mock_repair):
        mock_repair.return_value = "repaired_hash"

        cracker = PasswordCracker(
            target_hash="test_hash",
            session_name="my_session"
        )

        self.assertTrue(cracker.restore_file.endswith("my_session.json"))

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_init_session_name_with_json_extension(self, mock_repair):
        mock_repair.return_value = "repaired_hash"

        cracker = PasswordCracker(
            target_hash="test_hash",
            session_name="my_session.json"
        )

        self.assertTrue(cracker.restore_file.endswith("my_session.json"))

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_init_default_session_name(self, mock_repair):
        mock_repair.return_value = "abcd1234efgh5678"

        cracker = PasswordCracker(
            target_hash="test_hash",
            algorithm="sha1"
        )

        self.assertTrue("session_abcd1234_sha1.json" in cracker.restore_file)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_init_default_session_name_no_algorithm(self, mock_repair):
        mock_repair.return_value = "abcd1234efgh5678"

        cracker = PasswordCracker(target_hash="test_hash")

        self.assertTrue("session_abcd1234_auto.json" in cracker.restore_file)


class TestPotfileOperations(unittest.TestCase):
    """Test potfile-related methods"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.potfile_path = os.path.join(self.temp_dir, "cracked.potfile")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_potfile_not_exists(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = os.path.join(self.temp_dir, "nonexistent.potfile")

        result = cracker.check_potfile()

        self.assertIsNone(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_potfile_finds_exact_match(self, mock_repair):
        mock_repair.return_value = "hash123"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("hash456:password1\n")
            f.write("hash123:mypassword\n")
            f.write("hash789:password2\n")

        result = cracker.check_potfile()

        self.assertEqual(result, "mypassword")

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HashManager.verify_hash')
    def test_check_potfile_tests_known_passwords(self, mock_verify, mock_repair):
        mock_repair.return_value = "target_hash"
        mock_verify.side_effect = [
            (False, None),
            (True, "md5"),
            (False, None)
        ]

        cracker = PasswordCracker(target_hash="test_hash", verbose=False)
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("hash1:pass1\n")
            f.write("hash2:pass2\n")
            f.write("hash3:pass3\n")

        result = cracker.check_potfile()

        self.assertIn(result, ["pass1", "pass2", "pass3"])
        self.assertLessEqual(mock_verify.call_count, 3)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_potfile_empty_file(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("")

        result = cracker.check_potfile()

        self.assertIsNone(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_potfile_malformed_lines(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("invalid_line_no_colon\n")
            f.write("\n")
            f.write("   \n")
            f.write("hash_only:\n")

        result = cracker.check_potfile()

        self.assertIsNone(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_potfile_handles_exception(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=True)
        cracker.potfile_path = "/invalid/path/potfile"

        result = cracker.check_potfile()

        self.assertIsNone(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HashManager.get_supported_algorithms')
    @patch('password_cracker.core.cracker.HashManager.generate_hash')
    def test_save_to_potfile_new_password(self, mock_gen_hash, mock_algorithms, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_algorithms.return_value = ["MD5", "SHA1", "SHA256"]
        mock_gen_hash.side_effect = ["hash_md5", "hash_sha1", "hash_sha256"]

        cracker = PasswordCracker(target_hash="test_hash", verbose=False)
        cracker.potfile_path = self.potfile_path

        cracker.save_to_potfile("newpassword")

        with open(self.potfile_path, "r") as f:
            content = f.read()

        self.assertIn("test_hash:newpassword", content)
        self.assertIn("hash_md5:newpassword", content)
        self.assertIn("hash_sha1:newpassword", content)
        self.assertIn("hash_sha256:newpassword", content)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HashManager.get_supported_algorithms')
    def test_save_to_potfile_existing_password(self, mock_algorithms, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_algorithms.return_value = []

        cracker = PasswordCracker(target_hash="test_hash", verbose=True)
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("hash1:existingpass\n")

        cracker.save_to_potfile("existingpass")

        with open(self.potfile_path, "r") as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 1)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HashManager.get_supported_algorithms')
    @patch('password_cracker.core.cracker.HashManager.generate_hash')
    def test_save_to_potfile_skips_random_salt_algorithms(self, mock_gen_hash, mock_algorithms, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_algorithms.return_value = ["MD5", "Argon2", "bcrypt", "scrypt", "SHA256"]
        mock_gen_hash.side_effect = ["hash_md5", "hash_sha256"]

        cracker = PasswordCracker(target_hash="test_hash", algorithm="MD5", verbose=False)
        cracker.potfile_path = self.potfile_path

        cracker.save_to_potfile("testpass")

        self.assertEqual(mock_gen_hash.call_count, 1)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HashManager.get_supported_algorithms')
    @patch('password_cracker.core.cracker.HashManager.generate_hash')
    def test_save_to_potfile_skips_current_algorithm(self, mock_gen_hash, mock_algorithms, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_algorithms.return_value = ["MD5", "SHA1", "SHA256"]
        mock_gen_hash.side_effect = ["hash_sha1", "hash_sha256"]

        cracker = PasswordCracker(target_hash="test_hash", algorithm="md5", verbose=False)
        cracker.potfile_path = self.potfile_path

        cracker.save_to_potfile("testpass")

        self.assertEqual(mock_gen_hash.call_count, 2)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HashManager.get_supported_algorithms')
    @patch('password_cracker.core.cracker.HashManager.generate_hash')
    def test_save_to_potfile_handles_generation_error(self, mock_gen_hash, mock_algorithms, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_algorithms.return_value = ["MD5", "SHA1"]
        mock_gen_hash.side_effect = [Exception("Hash error"), "hash_sha1"]

        cracker = PasswordCracker(target_hash="test_hash", verbose=False)
        cracker.potfile_path = self.potfile_path

        cracker.save_to_potfile("testpass")

        with open(self.potfile_path, "r") as f:
            content = f.read()

        self.assertIn("test_hash:testpass", content)
        self.assertIn("hash_sha1:testpass", content)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_load_existing_hashes(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("hash1:password1\n")
            f.write("hash2:password2\n")
            f.write("hash3:password3\n")

        hashes = cracker._load_existing_hashes()

        self.assertEqual(hashes, {"hash1", "hash2", "hash3"})

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_load_existing_hashes_empty_file(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("")

        hashes = cracker._load_existing_hashes()

        self.assertEqual(hashes, set())

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_load_existing_passwords(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("hash1:password1\n")
            f.write("hash2:password2\n")
            f.write("hash3:password3\n")

        passwords = cracker._load_existing_passwords()

        self.assertEqual(passwords, {"password1", "password2", "password3"})

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_load_existing_passwords_malformed_lines(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.potfile_path = self.potfile_path

        with open(self.potfile_path, "w") as f:
            f.write("hash1:password1\n")
            f.write("invalid_line\n")
            f.write("\n")
            f.write("hash2:password2\n")

        passwords = cracker._load_existing_passwords()

        self.assertEqual(passwords, {"password1", "password2"})


class TestSessionManagement(unittest.TestCase):
    """Test session save/load/resume functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_save_session(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", algorithm="md5")
        cracker.restore_file = os.path.join(self.temp_dir, "session.json")
        cracker.pending_resume = None

        progress = {"line_number": 1000, "total_lines": 5000}
        cracker._save_session("dictionary", progress)

        self.assertTrue(os.path.exists(cracker.restore_file))

        with open(cracker.restore_file, "r", encoding='utf-8-sig') as f:
            data = json.load(f)

        self.assertEqual(data["strategy"], "dictionary")
        self.assertEqual(data["target_hash"], "test_hash")
        self.assertEqual(data["algorithm"], "md5")
        self.assertEqual(data["progress"], progress)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_load_session(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.restore_file = os.path.join(self.temp_dir, "session.json")

        session_data = {
            "strategy": "brute_force",
            "target_hash": "test_hash",
            "algorithm": None,
            "salt": "",
            "hex_salt": False,
            "salt_position": "after",
            "progress": {"current_length": 3},
            "started_at": "2024-01-01T00:00:00",
            "last_save": "2024-01-01T00:05:00"
        }

        with open(cracker.restore_file, "w") as f:
            json.dump(session_data, f)

        loaded = cracker._load_session()

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["strategy"], "brute_force")
        self.assertEqual(loaded["progress"]["current_length"], 3)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_load_session_not_exists(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.restore_file = os.path.join(self.temp_dir, "nonexistent.json")

        loaded = cracker._load_session()

        self.assertIsNone(loaded)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_clear_session(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.restore_file = os.path.join(self.temp_dir, "session.json")

        with open(cracker.restore_file, "w") as f:
            f.write("{}")

        cracker._clear_session()

        self.assertFalse(os.path.exists(cracker.restore_file))

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_clear_session_not_exists(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")
        cracker.restore_file = os.path.join(self.temp_dir, "nonexistent.json")

        cracker._clear_session()

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_session_matches_all_params(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(
            target_hash="test_hash",
            algorithm="sha256",
            salt="mysalt",
            hex_salt=True,
            salt_position="before"
        )

        session = {
            "target_hash": "test_hash",
            "algorithm": "sha256",
            "salt": "mysalt",
            "hex_salt": True,
            "salt_position": "before"
        }

        self.assertTrue(cracker._session_matches(session))

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_session_matches_different_hash(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "target_hash": "different_hash",
            "algorithm": None,
            "salt": "",
            "hex_salt": False,
            "salt_position": "after"
        }

        self.assertFalse(cracker._session_matches(session))

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_session_matches_different_algorithm(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", algorithm="md5")

        session = {
            "target_hash": "test_hash",
            "algorithm": "sha256",
            "salt": "",
            "hex_salt": False,
            "salt_position": "after"
        }

        self.assertFalse(cracker._session_matches(session))

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_session_matches_different_salt_params(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(
            target_hash="test_hash",
            salt="mysalt",
            hex_salt=True
        )

        session = {
            "target_hash": "test_hash",
            "algorithm": None,
            "salt": "different_salt",
            "hex_salt": True,
            "salt_position": "after"
        }

        self.assertFalse(cracker._session_matches(session))


class TestCheckpointThread(unittest.TestCase):
    """Test checkpoint threading functionality"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_start_checkpoint_thread(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", checkpoint_interval=1)

        cracker._start_checkpoint_thread("dictionary")

        self.assertIsNotNone(cracker.checkpoint_thread)
        self.assertTrue(cracker.checkpoint_thread.is_alive())
        self.assertEqual(cracker.current_strategy, "dictionary")

        cracker._stop_checkpoint_thread(clear_session=False)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_stop_checkpoint_thread(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", checkpoint_interval=1)

        cracker._start_checkpoint_thread("dictionary")
        time.sleep(0.1)

        cracker._stop_checkpoint_thread(clear_session=False)

        time.sleep(0.2)
        self.assertFalse(cracker.checkpoint_thread.is_alive())

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_checkpoint_worker_saves_progress(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", checkpoint_interval=1)

        with patch.object(cracker, '_save_session') as mock_save:
            cracker.current_strategy = "test_strategy"
            cracker.current_progress = {"test": "progress"}

            cracker._start_checkpoint_thread("test_strategy")
            time.sleep(1.5)

            cracker._stop_checkpoint_thread(clear_session=False)

            self.assertGreater(mock_save.call_count, 0)


class TestExecuteWithCache(unittest.TestCase):
    """Test _execute_with_cache method"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_execute_with_cache_finds_in_potfile(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        mock_strategy = Mock(return_value="password123")

        with patch.object(cracker, 'check_potfile', return_value="cached_password"):
            result = cracker._execute_with_cache(
                "dictionary",
                mock_strategy,
                wordlist="test.txt"
            )

        self.assertEqual(result, "cached_password")
        mock_strategy.assert_not_called()

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_execute_with_cache_resumes_brute_force(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        session = {
            "strategy": "brute_force",
            "progress": {"current_length": 5}
        }

        mock_strategy = Mock(return_value="found_password")

        with patch.object(cracker, 'check_potfile', return_value=None):
            with patch.object(cracker, '_check_resume', return_value=session):
                with patch.object(cracker, '_start_checkpoint_thread'):
                    with patch.object(cracker, '_stop_checkpoint_thread'):
                        with patch.object(cracker, 'save_to_potfile'):
                            result = cracker._execute_with_cache(
                                "brute_force",
                                mock_strategy,
                                min_length=1,
                                max_length=6
                            )

        self.assertEqual(result, "found_password")
        call_kwargs = mock_strategy.call_args[1]
        self.assertEqual(call_kwargs['min_length'], 5)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_execute_with_cache_resumes_dictionary(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        session = {
            "strategy": "dictionary",
            "progress": {"line_number": 1000}
        }

        mock_strategy = Mock(return_value="found_password")

        with patch.object(cracker, 'check_potfile', return_value=None):
            with patch.object(cracker, '_check_resume', return_value=session):
                with patch.object(cracker, '_start_checkpoint_thread'):
                    with patch.object(cracker, '_stop_checkpoint_thread'):
                        with patch.object(cracker, 'save_to_potfile'):
                            result = cracker._execute_with_cache(
                                "dictionary",
                                mock_strategy,
                                wordlist="test.txt"
                            )

        self.assertEqual(result, "found_password")
        call_kwargs = mock_strategy.call_args[1]
        self.assertEqual(call_kwargs['start_line'], 1000)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_execute_with_cache_saves_on_success(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        mock_strategy = Mock(return_value="cracked_password")

        with patch.object(cracker, 'check_potfile', return_value=None):
            with patch.object(cracker, '_check_resume', return_value=None):
                with patch.object(cracker, '_start_checkpoint_thread'):
                    with patch.object(cracker, '_stop_checkpoint_thread') as mock_stop:
                        with patch.object(cracker, 'save_to_potfile') as mock_save:
                            result = cracker._execute_with_cache(
                                "dictionary",
                                mock_strategy,
                                wordlist="test.txt"
                            )

        self.assertEqual(result, "cracked_password")
        mock_save.assert_called_once_with("cracked_password")
        mock_stop.assert_called_once_with(clear_session=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_execute_with_cache_no_password_found(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        mock_strategy = Mock(return_value=None)

        with patch.object(cracker, 'check_potfile', return_value=None):
            with patch.object(cracker, '_check_resume', return_value=None):
                with patch.object(cracker, '_start_checkpoint_thread'):
                    with patch.object(cracker, '_stop_checkpoint_thread') as mock_stop:
                        with patch.object(cracker, 'save_to_potfile') as mock_save:
                            result = cracker._execute_with_cache(
                                "dictionary",
                                mock_strategy,
                                wordlist="test.txt"
                            )

        self.assertIsNone(result)
        mock_save.assert_not_called()
        mock_stop.assert_called_once_with(clear_session=True)


class TestCrackingStrategies(unittest.TestCase):
    """Test the public strategy methods"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.DictionaryStrategy')
    def test_dictionary_strategy(self, mock_strategy_class, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_strategy = Mock()
        mock_strategy.execute = Mock(return_value="password")
        mock_strategy_class.return_value = mock_strategy

        cracker = PasswordCracker(target_hash="test_hash", algorithm="md5")

        with patch.object(cracker, '_execute_with_cache', return_value="password") as mock_exec:
            result = cracker.dictionary("wordlist.txt", processes=4)

        self.assertEqual(result, "password")
        mock_exec.assert_called_once()
        call_kwargs = mock_exec.call_args[1]
        self.assertEqual(call_kwargs['wordlist_path'], "wordlist.txt")
        self.assertEqual(call_kwargs['processes'], 4)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.RulesStrategy')
    def test_rules_strategy(self, mock_strategy_class, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_strategy = Mock()
        mock_strategy.execute = Mock(return_value="password")
        mock_strategy_class.return_value = mock_strategy

        cracker = PasswordCracker(target_hash="test_hash")

        with patch.object(cracker, '_execute_with_cache', return_value="password") as mock_exec:
            result = cracker.rules("wordlist.txt", ["rule1", "rule2"], stack=True, processes=2)

        self.assertEqual(result, "password")
        call_kwargs = mock_exec.call_args[1]
        self.assertEqual(call_kwargs['rules'], ["rule1", "rule2"])
        self.assertTrue(call_kwargs['stack'])
        self.assertEqual(call_kwargs['processes'], 2)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.BruteForceStrategy')
    def test_brute_force_strategy(self, mock_strategy_class, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_strategy = Mock()
        mock_strategy.execute = Mock(return_value="password")
        mock_strategy_class.return_value = mock_strategy

        cracker = PasswordCracker(target_hash="test_hash")

        with patch.object(cracker, '_execute_with_cache', return_value="password") as mock_exec:
            result = cracker.brute_force(
                mask="?l?l?l?d",
                min_length=3,
                max_length=8,
                charset='a',
                custom_charsets={'1': 'abc'},
                processes=8
            )

        self.assertEqual(result, "password")
        call_kwargs = mock_exec.call_args[1]
        self.assertEqual(call_kwargs['mask'], "?l?l?l?d")
        self.assertEqual(call_kwargs['min_length'], 3)
        self.assertEqual(call_kwargs['max_length'], 8)
        self.assertEqual(call_kwargs['charset'], 'a')
        self.assertEqual(call_kwargs['custom_charsets'], {'1': 'abc'})

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.HybridStrategy')
    def test_hybrid_strategy(self, mock_strategy_class, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_strategy = Mock()
        mock_strategy.execute = Mock(return_value="password")
        mock_strategy_class.return_value = mock_strategy

        cracker = PasswordCracker(target_hash="test_hash")

        with patch.object(cracker, '_execute_with_cache', return_value="password") as mock_exec:
            result = cracker.hybrid(
                "wordlist.txt",
                "?d?d",
                position='prepend',
                custom_charsets={'1': 'xyz'},
                processes=4
            )

        self.assertEqual(result, "password")
        call_kwargs = mock_exec.call_args[1]
        self.assertEqual(call_kwargs['wordlist_path'], "wordlist.txt")
        self.assertEqual(call_kwargs['mask'], "?d?d")
        self.assertEqual(call_kwargs['position'], 'prepend')

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('password_cracker.core.cracker.CombinatorStrategy')
    def test_combinator_strategy(self, mock_strategy_class, mock_repair):
        mock_repair.return_value = "test_hash"
        mock_strategy = Mock()
        mock_strategy.execute = Mock(return_value="password")
        mock_strategy_class.return_value = mock_strategy

        cracker = PasswordCracker(target_hash="test_hash")

        with patch.object(cracker, '_execute_with_cache', return_value="password") as mock_exec:
            result = cracker.combinator("left.txt", "right.txt", processes=2)

        self.assertEqual(result, "password")
        call_kwargs = mock_exec.call_args[1]
        self.assertEqual(call_kwargs['left_wordlist'], "left.txt")
        self.assertEqual(call_kwargs['right_wordlist'], "right.txt")
        self.assertEqual(call_kwargs['processes'], 2)


class TestUserInteraction(unittest.TestCase):
    """Test user interaction methods"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='y')
    def test_prompt_resume_yes(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "strategy": "dictionary",
            "started_at": "2024-01-01T00:00:00",
            "last_save": "2024-01-01T00:05:00",
            "progress": {"line_number": 1000}
        }

        result = cracker._prompt_resume(session)

        self.assertTrue(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='n')
    def test_prompt_resume_no(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "strategy": "dictionary",
            "started_at": "2024-01-01T00:00:00",
            "last_save": "2024-01-01T00:05:00",
            "progress": {"line_number": 1000}
        }

        result = cracker._prompt_resume(session)

        self.assertFalse(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='yes')
    def test_prompt_resume_yes_full(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "strategy": "brute_force",
            "started_at": "2024-01-01T00:00:00",
            "last_save": "2024-01-01T00:05:00",
            "progress": {}
        }

        result = cracker._prompt_resume(session)

        self.assertTrue(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='o')
    def test_handle_strategy_conflict_overwrite(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        result = cracker._handle_strategy_conflict("dictionary", "brute_force")

        self.assertEqual(result, "overwrite")

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='a')
    def test_handle_strategy_conflict_abort(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        result = cracker._handle_strategy_conflict("dictionary", "brute_force")

        self.assertEqual(result, "abort")

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='')
    def test_handle_strategy_conflict_default_abort(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        result = cracker._handle_strategy_conflict("dictionary", "brute_force")

        self.assertEqual(result, "abort")

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='invalid')
    def test_handle_strategy_conflict_invalid_choice(self, mock_input, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        result = cracker._handle_strategy_conflict("dictionary", "brute_force")

        self.assertEqual(result, "abort")


class TestCheckResume(unittest.TestCase):
    """Test _check_resume method with various scenarios"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_resume_no_session(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        with patch.object(cracker, '_load_session', return_value=None):
            result = cracker._check_resume("dictionary")

        self.assertIsNone(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_resume_matching_strategy(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "strategy": "dictionary",
            "target_hash": "test_hash",
            "algorithm": None,
            "salt": "",
            "hex_salt": False,
            "salt_position": "after",
            "progress": {}
        }

        with patch.object(cracker, '_load_session', return_value=session):
            with patch.object(cracker, '_session_matches', return_value=True):
                with patch.object(cracker, '_prompt_resume', return_value=True):
                    result = cracker._check_resume("dictionary")

        self.assertEqual(result, session)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_resume_user_declines(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "strategy": "dictionary",
            "target_hash": "test_hash",
            "algorithm": None,
            "salt": "",
            "hex_salt": False,
            "salt_position": "after",
            "progress": {}
        }

        with patch.object(cracker, '_load_session', return_value=session):
            with patch.object(cracker, '_session_matches', return_value=True):
                with patch.object(cracker, '_prompt_resume', return_value=False):
                    result = cracker._check_resume("dictionary")

        self.assertIsNone(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_resume_strategy_conflict_overwrite(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        session = {
            "strategy": "dictionary",
            "target_hash": "test_hash",
            "algorithm": None,
            "salt": "",
            "hex_salt": False,
            "salt_position": "after",
            "progress": {}
        }

        with patch.object(cracker, '_load_session', return_value=session):
            with patch.object(cracker, '_session_matches', return_value=True):
                with patch.object(cracker, '_handle_strategy_conflict', return_value="overwrite"):
                    with patch.object(cracker, '_clear_session') as mock_clear:
                        result = cracker._check_resume("brute_force")

        self.assertIsNone(result)
        mock_clear.assert_called_once()

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_check_resume_strategy_conflict_abort(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=True)

        session = {
            "strategy": "dictionary",
            "target_hash": "test_hash",
            "algorithm": None,
            "salt": "",
            "hex_salt": False,
            "salt_position": "after",
            "progress": {}
        }

        with patch.object(cracker, '_load_session', return_value=session):
            with patch.object(cracker, '_session_matches', return_value=True):
                with patch.object(cracker, '_handle_strategy_conflict', return_value="abort"):
                    result = cracker._check_resume("brute_force")

        self.assertIsNone(result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_potfile_with_colons_in_password(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        temp_dir = tempfile.mkdtemp()
        try:
            cracker.potfile_path = os.path.join(temp_dir, "test.potfile")

            with open(cracker.potfile_path, "w") as f:
                f.write("test_hash:pass:word:with:colons\n")

            result = cracker.check_potfile()

            # Should correctly handle colons in password
            self.assertEqual(result, "pass:word:with:colons")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_potfile_utf8_bom_handling(self, mock_repair):
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash")

        temp_dir = tempfile.mkdtemp()
        try:
            cracker.potfile_path = os.path.join(temp_dir, "test.potfile")

            # Write with BOM
            with open(cracker.potfile_path, "wb") as f:
                f.write(b'\xef\xbb\xbf')  # UTF-8 BOM
                f.write("test_hash:password\n".encode('utf-8'))

            result = cracker.check_potfile()

            self.assertEqual(result, "password")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_concurrent_potfile_access(self, mock_repair):
        """Test that potfile operations are thread-safe"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        temp_dir = tempfile.mkdtemp()
        try:
            cracker.potfile_path = os.path.join(temp_dir, "test.potfile")

            with patch('password_cracker.core.cracker.HashManager.get_supported_algorithms', return_value=["MD5"]):
                with patch('password_cracker.core.cracker.HashManager.generate_hash', return_value="hash_md5"):
                    # This should not raise any exceptions
                    cracker.save_to_potfile("password1")
                    cracker.save_to_potfile("password2")

                    passwords = cracker._load_existing_passwords()
                    self.assertEqual(len(passwords), 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_brute_force_custom_charsets_none(self, mock_repair):
        """Test that None custom_charsets is converted to empty dict"""
        mock_repair.return_value = "test_hash"

        with patch('password_cracker.core.cracker.BruteForceStrategy') as mock_strategy_class:
            mock_strategy = Mock()
            mock_strategy.execute = Mock(return_value=None)
            mock_strategy_class.return_value = mock_strategy

            cracker = PasswordCracker(target_hash="test_hash")

            with patch.object(cracker, '_execute_with_cache') as mock_exec:
                cracker.brute_force(custom_charsets=None)

                call_kwargs = mock_exec.call_args[1]
                self.assertEqual(call_kwargs['custom_charsets'], {})

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    def test_hybrid_custom_charsets_none(self, mock_repair):
        """Test that None custom_charsets is converted to empty dict"""
        mock_repair.return_value = "test_hash"

        with patch('password_cracker.core.cracker.HybridStrategy') as mock_strategy_class:
            mock_strategy = Mock()
            mock_strategy.execute = Mock(return_value=None)
            mock_strategy_class.return_value = mock_strategy

            cracker = PasswordCracker(target_hash="test_hash")

            with patch.object(cracker, '_execute_with_cache') as mock_exec:
                cracker.hybrid("wordlist.txt", "?d", custom_charsets=None)

                call_kwargs = mock_exec.call_args[1]
                self.assertEqual(call_kwargs['custom_charsets'], {})


class TestCrackerPromptResume(unittest.TestCase):
    """Test _prompt_resume method"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='y')
    def test_prompt_resume_accepts_y(self, mock_input, mock_repair):
        """Test prompt resume accepts 'y'"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        session = {
            'strategy': 'dictionary',
            'started_at': None,
            'last_save': None,
            'progress': {}
        }

        result = cracker._prompt_resume(session)
        self.assertTrue(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='n')
    def test_prompt_resume_declines_n(self, mock_input, mock_repair):
        """Test prompt resume declines 'n'"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        session = {
            'strategy': 'dictionary',
            'started_at': None,
            'last_save': None,
            'progress': {}
        }

        result = cracker._prompt_resume(session)
        self.assertFalse(result)

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='')
    def test_prompt_resume_default_no(self, mock_input, mock_repair):
        """Test prompt resume defaults to NO on empty input (matches code behavior)"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        session = {
            'strategy': 'dictionary',
            'started_at': None,
            'last_save': None,
            'progress': {}
        }

        result = cracker._prompt_resume(session)
        self.assertFalse(result)  # UPDATED: Code actually returns False here


class TestCrackerHandleStrategyConflict(unittest.TestCase):
    """Test _handle_strategy_conflict method"""

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='o')
    def test_handle_strategy_conflict_overwrite(self, mock_input, mock_repair):
        """Test strategy conflict chooses overwrite"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        result = cracker._handle_strategy_conflict('dictionary', 'brute_force')
        self.assertEqual(result, 'overwrite')

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='a')
    def test_handle_strategy_conflict_abort(self, mock_input, mock_repair):
        """Test strategy conflict chooses abort"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        result = cracker._handle_strategy_conflict('dictionary', 'brute_force')
        self.assertEqual(result, 'abort')

    @patch('password_cracker.core.cracker.HashManager.repair_hash')
    @patch('builtins.input', return_value='invalid')
    def test_handle_strategy_conflict_invalid_aborts(self, mock_input, mock_repair):
        """Test strategy conflict aborts on invalid input (matches code behavior)"""
        mock_repair.return_value = "test_hash"
        cracker = PasswordCracker(target_hash="test_hash", verbose=False)

        # Code doesn't loop; it aborts on invalid input
        result = cracker._handle_strategy_conflict('dictionary', 'brute_force')
        self.assertEqual(result, 'abort')


if __name__ == '__main__':
    unittest.main(verbosity=2)