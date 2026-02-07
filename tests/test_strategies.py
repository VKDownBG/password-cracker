"""
Unit tests for attack strategy implementations.
Tests dictionary, combinator, brute-force, hybrid, and rules-based strategies.
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import Mock, patch, call

from password_cracker.strategies.dictionary import DictionaryStrategy
from password_cracker.strategies.combinator import CombinatorStrategy
from password_cracker.strategies.brute_force import BruteForceStrategy
from password_cracker.strategies.hybrid import HybridStrategy
from password_cracker.strategies.rules import RulesStrategy
from password_cracker.core.hasher import HashManager

# --- HELPER: MOCK POOL FOR TESTING ---
# Forces "multiprocessing" code to run synchronously in the main thread.
# This fixes the Windows deadlock/infinite hanging issue.
class MockPool:
    def __init__(self, processes=None, initializer=None, initargs=()):
        if initializer and initargs:
            initializer(*initargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def terminate(self):
        pass

    def join(self):
        pass

    def imap_unordered(self, func, iterable, chunksize=1):
        # Run loop synchronously
        for item in iterable:
            yield func(item)

# --- GLOBAL CALLBACK DATA ---
# Must be global to survive pickling (prevents "Can't pickle local object" error)
PROGRESS_DATA = []

def global_progress_callback(data):
    PROGRESS_DATA.append(data)


class TestDictionaryStrategy(unittest.TestCase):
    """Test dictionary attack strategy"""

    def setUp(self):
        self.strategy = DictionaryStrategy()
        self.test_password = "password"
        self.test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5("password")

        # Create temporary wordlist
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.wordlist.write("wrong1\nwrong2\npassword\nwrong3\n")
        self.wordlist.close()

    def tearDown(self):
        if os.path.exists(self.wordlist.name):
            try: os.unlink(self.wordlist.name)
            except: pass

    def test_dictionary_single_threaded_found(self):
        result = self.strategy.execute(
            target_hash=self.test_hash, algorithm="MD5", verbose=False,
            processes=1, wordlist_path=self.wordlist.name
        )
        self.assertEqual(result, self.test_password)

    def test_dictionary_multiprocess_found(self):
        # Apply MockPool to prevent hanging
        with patch('password_cracker.strategies.dictionary.Pool', side_effect=MockPool):
            result = self.strategy.execute(
                target_hash=self.test_hash, algorithm="MD5", verbose=False,
                processes=2, wordlist_path=self.wordlist.name
            )
        self.assertEqual(result, self.test_password)

    def test_dictionary_not_found(self):
        wrong_hash = "0" * 32
        result = self.strategy.execute(
            target_hash=wrong_hash, algorithm="MD5", verbose=False,
            processes=1, wordlist_path=self.wordlist.name
        )
        self.assertIsNone(result)

    def test_dictionary_with_salt(self):
        salted_hash = HashManager.generate_hash("password", "MD5", salt="mysalt")
        result = self.strategy.execute(
            target_hash=salted_hash, algorithm="MD5", salt="mysalt",
            verbose=False, processes=1, wordlist_path=self.wordlist.name
        )
        self.assertEqual(result, self.test_password)

    def test_dictionary_wordlist_not_found(self):
        result = self.strategy.execute(
            target_hash=self.test_hash, algorithm="MD5", verbose=False,
            processes=1, wordlist_path="nonexistent.txt"
        )
        self.assertIsNone(result)

    def test_dictionary_missing_wordlist_param(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash=self.test_hash, algorithm="MD5",
                verbose=False, processes=1
            )

    def test_dictionary_auto_detect_algorithm(self):
        result = self.strategy.execute(
            target_hash=self.test_hash, algorithm=None, verbose=False,
            processes=1, wordlist_path=self.wordlist.name
        )
        self.assertEqual(result, self.test_password)

    def test_dictionary_resume_from_line(self):
        result = self.strategy.execute(
            target_hash=self.test_hash, algorithm="MD5", verbose=False,
            processes=1, start_line=2, wordlist_path=self.wordlist.name
        )
        self.assertEqual(result, self.test_password)


class TestCombinatorStrategy(unittest.TestCase):
    """Test combinator attack strategy"""

    def setUp(self):
        self.strategy = CombinatorStrategy()
        self.test_hash = HashManager.generate_hash("john123", "MD5")

        self.left_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.left_wordlist.write("admin\njohn\nuser\n")
        self.left_wordlist.close()

        self.right_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.right_wordlist.write("456\n123\n789\n")
        self.right_wordlist.close()

    def tearDown(self):
        for f in [self.left_wordlist, self.right_wordlist]:
            if os.path.exists(f.name):
                try: os.unlink(f.name)
                except: pass

    def test_combinator_single_threaded_found(self):
        result = self.strategy.execute(
            target_hash=self.test_hash, algorithm="MD5", verbose=False, processes=1,
            left_wordlist=self.left_wordlist.name, right_wordlist=self.right_wordlist.name
        )
        self.assertEqual(result, "john123")

    def test_combinator_multiprocess_found(self):
        with patch('password_cracker.strategies.combinator.Pool', side_effect=MockPool):
            result = self.strategy.execute(
                target_hash=self.test_hash, algorithm="MD5", verbose=False, processes=2,
                left_wordlist=self.left_wordlist.name, right_wordlist=self.right_wordlist.name
            )
        self.assertEqual(result, "john123")

    def test_combinator_not_found(self):
        wrong_hash = "0" * 32
        result = self.strategy.execute(
            target_hash=wrong_hash, algorithm="MD5", verbose=False, processes=1,
            left_wordlist=self.left_wordlist.name, right_wordlist=self.right_wordlist.name
        )
        self.assertIsNone(result)

    def test_combinator_missing_left_wordlist(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash=self.test_hash, algorithm="MD5", verbose=False, processes=1,
                right_wordlist=self.right_wordlist.name
            )

    def test_combinator_missing_right_wordlist(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash=self.test_hash, algorithm="MD5", verbose=False, processes=1,
                left_wordlist=self.left_wordlist.name
            )


class TestBruteForceStrategy(unittest.TestCase):
    """Test brute-force attack strategy"""

    def setUp(self):
        self.strategy = BruteForceStrategy()

    def test_bruteforce_mask_simple(self):
        test_hash = HashManager.generate_hash("abc", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1, mask="?l?l?l"
        )
        self.assertEqual(result, "abc")

    def test_bruteforce_mask_with_digits(self):
        test_hash = HashManager.generate_hash("ab12", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1, mask="?l?l?d?d"
        )
        self.assertEqual(result, "ab12")

    def test_bruteforce_custom_charset(self):
        test_hash = HashManager.generate_hash("XYZ", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            mask="?1?1?1", custom_charsets={'1': 'XYZ'}
        )
        self.assertEqual(result, "XYZ")

    def test_bruteforce_fixed_characters(self):
        test_hash = HashManager.generate_hash("a1b2c3", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1, mask="a?db?dc?d"
        )
        self.assertEqual(result, "a1b2c3")

    def test_bruteforce_incremental_mode(self):
        test_hash = HashManager.generate_hash("xy", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            mask=None, min_length=1, max_length=3, charset='l'
        )
        self.assertEqual(result, "xy")

    def test_bruteforce_not_found(self):
        wrong_hash = "0" * 32
        result = self.strategy.execute(
            target_hash=wrong_hash, algorithm="MD5", verbose=False, processes=1,
            mask="?l?l", min_length=1, max_length=2, charset='a'
        )
        self.assertIsNone(result)


class TestHybridStrategy(unittest.TestCase):
    """Test hybrid attack strategy"""

    def setUp(self):
        self.strategy = HybridStrategy()
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.wordlist.write("admin\npassword\nuser\n")
        self.wordlist.close()

    def tearDown(self):
        if os.path.exists(self.wordlist.name):
            try: os.unlink(self.wordlist.name)
            except: pass

    def test_hybrid_append_mask(self):
        test_hash = HashManager.generate_hash("password123", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, mask="?d?d?d", position="append"
        )
        self.assertEqual(result, "password123")

    def test_hybrid_prepend_mask(self):
        test_hash = HashManager.generate_hash("123password", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, mask="?d?d?d", position="prepend"
        )
        self.assertEqual(result, "123password")

    def test_hybrid_custom_charset(self):
        test_hash = HashManager.generate_hash("admin!@#", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, mask="?1?1?1", position="append",
            custom_charsets={'1': '!@#'}
        )
        self.assertEqual(result, "admin!@#")

    def test_hybrid_multiprocess(self):
        test_hash = HashManager.generate_hash("password123", "MD5")
        with patch('password_cracker.strategies.hybrid.Pool', side_effect=MockPool):
            result = self.strategy.execute(
                target_hash=test_hash, algorithm="MD5", verbose=False, processes=2,
                wordlist_path=self.wordlist.name, mask="?d?d?d", position="append"
            )
        self.assertEqual(result, "password123")

    def test_hybrid_missing_wordlist(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0"*32, algorithm="MD5", verbose=False, processes=1, mask="?d?d?d"
            )

    def test_hybrid_missing_mask(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0"*32, algorithm="MD5", verbose=False, processes=1, wordlist_path=self.wordlist.name
            )

    def test_hybrid_invalid_position(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0"*32, algorithm="MD5", verbose=False, processes=1,
                wordlist_path=self.wordlist.name, mask="?d?d?d", position="invalid"
            )


class TestRulesStrategy(unittest.TestCase):
    """Test rules-based attack strategy"""

    def setUp(self):
        self.strategy = RulesStrategy()
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.wordlist.write("password\nadmin\ntest\n")
        self.wordlist.close()

        self.rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.rules_file.write(":\n")  # No change
        self.rules_file.write("c\n")  # Capitalize
        self.rules_file.write("u\n")  # Uppercase
        self.rules_file.write("$1\n")  # Append 1
        self.rules_file.write("$2\n")  # Append 2
        self.rules_file.write("$3\n")  # Append 3
        self.rules_file.close()

    def tearDown(self):
        for f in [self.wordlist, self.rules_file]:
            if os.path.exists(f.name):
                try: os.unlink(f.name)
                except: pass

    def test_rules_no_change(self):
        test_hash = HashManager.generate_hash("password", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, rules=[":"]
        )
        self.assertEqual(result, "password")

    def test_rules_capitalize(self):
        test_hash = HashManager.generate_hash("Password", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, rules=["c"]
        )
        self.assertEqual(result, "Password")

    def test_rules_uppercase(self):
        test_hash = HashManager.generate_hash("PASSWORD", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, rules=["u"]
        )
        self.assertEqual(result, "PASSWORD")

    def test_rules_append(self):
        test_hash = HashManager.generate_hash("password123", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, stack=True, rules=["$1", "$2", "$3"]
        )
        self.assertEqual(result, "password123")

    def test_rules_from_file(self):
        test_hash = HashManager.generate_hash("Password", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, rules=[self.rules_file.name]
        )
        self.assertEqual(result, "Password")

    def test_rules_stacked(self):
        test_hash = HashManager.generate_hash("Password1", "MD5")
        result = self.strategy.execute(
            target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
            wordlist_path=self.wordlist.name, rules=["c", "$1"], stack=True
        )
        self.assertEqual(result, "Password1")

    def test_rules_multiprocess(self):
        test_hash = HashManager.generate_hash("Password", "MD5")
        with patch('password_cracker.strategies.rules.Pool', side_effect=MockPool):
            result = self.strategy.execute(
                target_hash=test_hash, algorithm="MD5", verbose=False, processes=2,
                wordlist_path=self.wordlist.name, rules=["c"]
            )
        self.assertEqual(result, "Password")

    def test_rules_missing_wordlist(self):
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0"*32, algorithm="MD5", verbose=False, processes=1, rules=["c"]
            )


class TestStrategyEdgeCases(unittest.TestCase):
    """Test edge cases and error handling for strategies"""

    def test_empty_wordlist(self):
        strategy = DictionaryStrategy()
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.close()
        try:
            result = strategy.execute(
                target_hash="0"*32, algorithm="MD5", verbose=False, processes=1,
                wordlist_path=wordlist.name
            )
            self.assertIsNone(result)
        finally:
            os.unlink(wordlist.name)

    def test_wordlist_with_unicode(self):
        strategy = DictionaryStrategy()
        unicode_password = "пароль"
        test_hash = HashManager.generate_hash(unicode_password, "MD5")
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.write("wrong\n")
        wordlist.write(f"{unicode_password}\n")
        wordlist.close()
        try:
            result = strategy.execute(
                target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
                wordlist_path=wordlist.name
            )
            self.assertEqual(result, unicode_password)
        finally:
            os.unlink(wordlist.name)

    def test_wordlist_with_empty_lines(self):
        strategy = DictionaryStrategy()
        test_hash = HashManager.generate_hash("password", "MD5")
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.write("\n   \npassword\n\n")
        wordlist.close()
        try:
            result = strategy.execute(
                target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
                wordlist_path=wordlist.name
            )
            self.assertEqual(result, "password")
        finally:
            os.unlink(wordlist.name)

    def test_wordlist_with_whitespace(self):
        strategy = DictionaryStrategy()
        test_hash = HashManager.generate_hash("password", "MD5")
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.write("  password  \n")
        wordlist.close()
        try:
            result = strategy.execute(
                target_hash=test_hash, algorithm="MD5", verbose=False, processes=1,
                wordlist_path=wordlist.name
            )
            self.assertEqual(result, "password")
        finally:
            os.unlink(wordlist.name)

    def test_brute_force_empty_charset(self):
        strategy = BruteForceStrategy()
        result = strategy.execute(
            target_hash="0"*32, algorithm="MD5", verbose=False, processes=1,
            mask="?1?1", custom_charsets={'1': ''}
        )
        self.assertIsNone(result)


class TestProgressCallback(unittest.TestCase):
    """Test progress callback functionality"""

    def setUp(self):
        global PROGRESS_DATA
        PROGRESS_DATA = []
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        # Ensure enough words to trigger callback
        for i in range(5000):
            self.wordlist.write(f"word{i}\n")
        self.wordlist.close()

    def tearDown(self):
        if os.path.exists(self.wordlist.name):
            try: os.unlink(self.wordlist.name)
            except: pass

    def test_dictionary_progress_callback(self):
        strategy = DictionaryStrategy()
        # Use MockPool AND force processes=2 to trigger any multiprocessing logic
        with patch('password_cracker.strategies.dictionary.Pool', side_effect=MockPool):
            strategy.execute(
                target_hash="0"*32, algorithm="MD5", verbose=False, processes=2,
                wordlist_path=self.wordlist.name, progress_callback=global_progress_callback
            )
        self.assertGreater(len(PROGRESS_DATA), 0)
        self.assertIn('line_number', PROGRESS_DATA[0])


if __name__ == '__main__':
    unittest.main()