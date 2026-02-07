"""
Unit tests for attack strategy implementations.
Tests dictionary, combinator, brute-force, hybrid, and rules-based strategies.
"""

import unittest
import tempfile
import os
from password_cracker.strategies.dictionary import DictionaryStrategy
from password_cracker.strategies.combinator import CombinatorStrategy
from password_cracker.strategies.brute_force import BruteForceStrategy
from password_cracker.strategies.hybrid import HybridStrategy
from password_cracker.strategies.rules import RulesStrategy
from password_cracker.core.hasher import HashManager


class TestDictionaryStrategy(unittest.TestCase):
    """Test dictionary attack strategy"""

    def setUp(self):
        """Set up test fixtures"""
        self.strategy = DictionaryStrategy()
        self.test_password = "password"
        self.test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5("password")

        # Create temporary wordlist
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.wordlist.write("wrong1\n")
        self.wordlist.write("wrong2\n")
        self.wordlist.write("password\n")
        self.wordlist.write("wrong3\n")
        self.wordlist.close()

    def tearDown(self):
        """Clean up test files"""
        os.unlink(self.wordlist.name)

    def test_dictionary_single_threaded_found(self):
        """Test dictionary attack finds password (single-threaded)"""
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name
        )

        self.assertEqual(result, self.test_password)

    def test_dictionary_multiprocess_found(self):
        """Test dictionary attack finds password (multiprocess)"""
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm="MD5",
            verbose=False,
            processes=2,
            wordlist_path=self.wordlist.name
        )

        self.assertEqual(result, self.test_password)

    def test_dictionary_not_found(self):
        """Test dictionary attack when password not in wordlist"""
        wrong_hash = "0" * 32

        result = self.strategy.execute(
            target_hash=wrong_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name
        )

        self.assertIsNone(result)

    def test_dictionary_with_salt(self):
        """Test dictionary attack with salt"""
        # Hash of "passwordmysalt"
        salted_hash = HashManager.generate_hash("password", "MD5", salt="mysalt")

        result = self.strategy.execute(
            target_hash=salted_hash,
            algorithm="MD5",
            salt="mysalt",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name
        )

        self.assertEqual(result, self.test_password)

    def test_dictionary_wordlist_not_found(self):
        """Test dictionary attack with non-existent wordlist"""
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path="nonexistent.txt"
        )

        self.assertIsNone(result)

    def test_dictionary_missing_wordlist_param(self):
        """Test dictionary attack without wordlist parameter"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash=self.test_hash,
                algorithm="MD5",
                verbose=False,
                processes=1
            )

    def test_dictionary_auto_detect_algorithm(self):
        """Test dictionary attack with algorithm auto-detection"""
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm=None,  # Auto-detect
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name
        )

        self.assertEqual(result, self.test_password)

    def test_dictionary_resume_from_line(self):
        """Test dictionary attack resuming from specific line"""
        # Starting from line 2 should skip "wrong1" and "wrong2"
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            start_line=2,
            wordlist_path=self.wordlist.name
        )

        self.assertEqual(result, self.test_password)


class TestCombinatorStrategy(unittest.TestCase):
    """Test combinator attack strategy"""

    def setUp(self):
        """Set up test fixtures"""
        self.strategy = CombinatorStrategy()
        # "john123" MD5 hash
        self.test_hash = HashManager.generate_hash("john123", "MD5")

        # Create left wordlist
        self.left_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.left_wordlist.write("admin\n")
        self.left_wordlist.write("john\n")
        self.left_wordlist.write("user\n")
        self.left_wordlist.close()

        # Create right wordlist
        self.right_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.right_wordlist.write("456\n")
        self.right_wordlist.write("123\n")
        self.right_wordlist.write("789\n")
        self.right_wordlist.close()

    def tearDown(self):
        """Clean up test files"""
        os.unlink(self.left_wordlist.name)
        os.unlink(self.right_wordlist.name)

    def test_combinator_single_threaded_found(self):
        """Test combinator attack finds password (single-threaded)"""
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            left_wordlist=self.left_wordlist.name,
            right_wordlist=self.right_wordlist.name
        )

        self.assertEqual(result, "john123")

    def test_combinator_multiprocess_found(self):
        """Test combinator attack finds password (multiprocess)"""
        result = self.strategy.execute(
            target_hash=self.test_hash,
            algorithm="MD5",
            verbose=False,
            processes=2,
            left_wordlist=self.left_wordlist.name,
            right_wordlist=self.right_wordlist.name
        )

        self.assertEqual(result, "john123")

    def test_combinator_not_found(self):
        """Test combinator attack when combination not found"""
        wrong_hash = "0" * 32

        result = self.strategy.execute(
            target_hash=wrong_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            left_wordlist=self.left_wordlist.name,
            right_wordlist=self.right_wordlist.name
        )

        self.assertIsNone(result)

    def test_combinator_missing_left_wordlist(self):
        """Test combinator attack without left wordlist"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash=self.test_hash,
                algorithm="MD5",
                verbose=False,
                processes=1,
                right_wordlist=self.right_wordlist.name
            )

    def test_combinator_missing_right_wordlist(self):
        """Test combinator attack without right wordlist"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash=self.test_hash,
                algorithm="MD5",
                verbose=False,
                processes=1,
                left_wordlist=self.left_wordlist.name
            )


class TestBruteForceStrategy(unittest.TestCase):
    """Test brute-force attack strategy"""

    def setUp(self):
        """Set up test fixtures"""
        self.strategy = BruteForceStrategy()

    def test_bruteforce_mask_simple(self):
        """Test brute-force with simple mask"""
        # "abc" MD5 hash
        test_hash = HashManager.generate_hash("abc", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask="?l?l?l"
        )

        self.assertEqual(result, "abc")

    def test_bruteforce_mask_with_digits(self):
        """Test brute-force with mask containing digits"""
        # "ab12" MD5 hash
        test_hash = HashManager.generate_hash("ab12", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask="?l?l?d?d"
        )

        self.assertEqual(result, "ab12")

    def test_bruteforce_custom_charset(self):
        """Test brute-force with custom charset"""
        # "XYZ" MD5 hash
        test_hash = HashManager.generate_hash("XYZ", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask="?1?1?1",
            custom_charsets={'1': 'XYZ'}
        )

        self.assertEqual(result, "XYZ")

    def test_bruteforce_fixed_characters(self):
        """Test brute-force with fixed characters in mask"""
        # "a1b2c3" MD5 hash
        test_hash = HashManager.generate_hash("a1b2c3", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask="a?db?dc?d"
        )

        self.assertEqual(result, "a1b2c3")

    def test_bruteforce_incremental_mode(self):
        """Test brute-force incremental mode"""
        # "xy" MD5 hash
        test_hash = HashManager.generate_hash("xy", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask=None,
            min_length=1,
            max_length=3,
            charset='l'  # Lowercase only
        )

        self.assertEqual(result, "xy")

    def test_bruteforce_not_found(self):
        """Test brute-force when password not found"""
        wrong_hash = "0" * 32

        result = self.strategy.execute(
            target_hash=wrong_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask="?l?l",
            min_length=1,
            max_length=2,
            charset='a'
        )

        self.assertIsNone(result)


class TestHybridStrategy(unittest.TestCase):
    """Test hybrid attack strategy"""

    def setUp(self):
        """Set up test fixtures"""
        self.strategy = HybridStrategy()

        # Create wordlist
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.wordlist.write("admin\n")
        self.wordlist.write("password\n")
        self.wordlist.write("user\n")
        self.wordlist.close()

    def tearDown(self):
        """Clean up test files"""
        os.unlink(self.wordlist.name)

    def test_hybrid_append_mask(self):
        """Test hybrid attack with mask appended to word"""
        # "password123" MD5 hash
        test_hash = HashManager.generate_hash("password123", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            mask="?d?d?d",
            position="append"
        )

        self.assertEqual(result, "password123")

    def test_hybrid_prepend_mask(self):
        """Test hybrid attack with mask prepended to word"""
        # "123password" MD5 hash
        test_hash = HashManager.generate_hash("123password", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            mask="?d?d?d",
            position="prepend"
        )

        self.assertEqual(result, "123password")

    def test_hybrid_custom_charset(self):
        """Test hybrid attack with custom charset"""
        # "admin!@#" MD5 hash
        test_hash = HashManager.generate_hash("admin!@#", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            mask="?1?1?1",
            position="append",
            custom_charsets={'1': '!@#'}
        )

        self.assertEqual(result, "admin!@#")

    def test_hybrid_multiprocess(self):
        """Test hybrid attack with multiprocessing"""
        test_hash = HashManager.generate_hash("password123", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=2,
            wordlist_path=self.wordlist.name,
            mask="?d?d?d",
            position="append"
        )

        self.assertEqual(result, "password123")

    def test_hybrid_missing_wordlist(self):
        """Test hybrid attack without wordlist parameter"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0" * 32,
                algorithm="MD5",
                verbose=False,
                processes=1,
                mask="?d?d?d"
            )

    def test_hybrid_missing_mask(self):
        """Test hybrid attack without mask parameter"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0" * 32,
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=self.wordlist.name
            )

    def test_hybrid_invalid_position(self):
        """Test hybrid attack with invalid position"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0" * 32,
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=self.wordlist.name,
                mask="?d?d?d",
                position="invalid"
            )


class TestRulesStrategy(unittest.TestCase):
    """Test rules-based attack strategy"""

    def setUp(self):
        """Set up test fixtures"""
        self.strategy = RulesStrategy()

        # Create wordlist
        self.wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.wordlist.write("password\n")
        self.wordlist.write("admin\n")
        self.wordlist.write("test\n")
        self.wordlist.close()

        # Create rules file
        self.rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        self.rules_file.write(":\n")  # No change
        self.rules_file.write("c\n")  # Capitalize
        self.rules_file.write("u\n")  # Uppercase
        self.rules_file.write("$1\n")  # Append 1
        self.rules_file.write("$2\n")  # Append 2
        self.rules_file.write("$3\n")  # Append 3
        self.rules_file.close()

    def tearDown(self):
        """Clean up test files"""
        os.unlink(self.wordlist.name)
        os.unlink(self.rules_file.name)

    def test_rules_no_change(self):
        """Test rules attack with no-change rule"""
        # "password" MD5 hash
        test_hash = HashManager.generate_hash("password", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            rules=[":"]  # No change rule
        )

        self.assertEqual(result, "password")

    def test_rules_capitalize(self):
        """Test rules attack with capitalize rule"""
        # "Password" MD5 hash
        test_hash = HashManager.generate_hash("Password", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            rules=["c"]  # Capitalize
        )

        self.assertEqual(result, "Password")

    def test_rules_uppercase(self):
        """Test rules attack with uppercase rule"""
        # "PASSWORD" MD5 hash
        test_hash = HashManager.generate_hash("PASSWORD", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            rules=["u"]  # Uppercase
        )

        self.assertEqual(result, "PASSWORD")

    def test_rules_append(self):
        """Test rules attack with append rule"""
        # "password123" MD5 hash
        test_hash = HashManager.generate_hash("password123", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            stack=True,
            rules=["$1", "$2", "$3"]  # Append 1, 2, 3
        )

        self.assertEqual(result, "password123")

    def test_rules_from_file(self):
        """Test rules attack loading rules from file"""
        # "Password" MD5 hash
        test_hash = HashManager.generate_hash("Password", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            rules=[self.rules_file.name]
        )

        self.assertEqual(result, "Password")

    def test_rules_stacked(self):
        """Test rules attack with stacked rules"""
        # Apply rules in sequence: capitalize then append 1
        # "password" -> "Password" -> "Password1"
        test_hash = HashManager.generate_hash("Password1", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=1,
            wordlist_path=self.wordlist.name,
            rules=["c", "$1"],
            stack=True
        )

        self.assertEqual(result, "Password1")

    def test_rules_multiprocess(self):
        """Test rules attack with multiprocessing"""
        test_hash = HashManager.generate_hash("Password", "MD5")

        result = self.strategy.execute(
            target_hash=test_hash,
            algorithm="MD5",
            verbose=False,
            processes=2,
            wordlist_path=self.wordlist.name,
            rules=["c"]
        )

        self.assertEqual(result, "Password")

    def test_rules_missing_wordlist(self):
        """Test rules attack without wordlist parameter"""
        with self.assertRaises(ValueError):
            self.strategy.execute(
                target_hash="0" * 32,
                algorithm="MD5",
                verbose=False,
                processes=1,
                rules=["c"]
            )


class TestStrategyEdgeCases(unittest.TestCase):
    """Test edge cases and error handling for strategies"""

    def test_empty_wordlist(self):
        """Test dictionary attack with empty wordlist"""
        strategy = DictionaryStrategy()

        # Create empty wordlist
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.close()

        try:
            result = strategy.execute(
                target_hash="0" * 32,
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=wordlist.name
            )

            self.assertIsNone(result)
        finally:
            os.unlink(wordlist.name)

    def test_wordlist_with_unicode(self):
        """Test dictionary attack with unicode passwords"""
        strategy = DictionaryStrategy()

        unicode_password = "пароль"  # Russian for "password"
        test_hash = HashManager.generate_hash(unicode_password, "MD5")

        # Create wordlist with unicode
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.write("wrong\n")
        wordlist.write(f"{unicode_password}\n")
        wordlist.close()

        try:
            result = strategy.execute(
                target_hash=test_hash,
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=wordlist.name
            )

            self.assertEqual(result, unicode_password)
        finally:
            os.unlink(wordlist.name)

    def test_wordlist_with_empty_lines(self):
        """Test dictionary attack with empty lines in wordlist"""
        strategy = DictionaryStrategy()

        test_hash = HashManager.generate_hash("password", "MD5")

        # Create wordlist with empty lines
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.write("\n")
        wordlist.write("   \n")
        wordlist.write("password\n")
        wordlist.write("\n")
        wordlist.close()

        try:
            result = strategy.execute(
                target_hash=test_hash,
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=wordlist.name
            )

            self.assertEqual(result, "password")
        finally:
            os.unlink(wordlist.name)

    def test_wordlist_with_whitespace(self):
        """Test dictionary attack with whitespace in passwords"""
        strategy = DictionaryStrategy()

        # Wordlist entries should be stripped
        test_hash = HashManager.generate_hash("password", "MD5")

        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        wordlist.write("  password  \n")
        wordlist.close()

        try:
            result = strategy.execute(
                target_hash=test_hash,
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=wordlist.name
            )

            self.assertEqual(result, "password")
        finally:
            os.unlink(wordlist.name)

    def test_brute_force_empty_charset(self):
        """Test brute-force with empty custom charset"""
        strategy = BruteForceStrategy()

        # This should handle gracefully or raise appropriate error
        result = strategy.execute(
            target_hash="0" * 32,
            algorithm="MD5",
            verbose=False,
            processes=1,
            mask="?1?1",
            custom_charsets={'1': ''}
        )

        # Should return None since charset is empty
        self.assertIsNone(result)


class TestProgressCallback(unittest.TestCase):
    """Test progress callback functionality"""

    def test_dictionary_progress_callback(self):
        """Test that progress callback is called during dictionary attack"""
        strategy = DictionaryStrategy()

        # Create wordlist
        wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8')
        for i in range(1000):
            wordlist.write(f"word{i}\n")
        wordlist.close()

        progress_calls = []

        def progress_callback(data):
            progress_calls.append(data)

        try:
            strategy.execute(
                target_hash="0" * 32,  # Won't find it
                algorithm="MD5",
                verbose=False,
                processes=1,
                wordlist_path=wordlist.name,
                progress_callback=progress_callback
            )

            # Should have been called at least once
            self.assertGreater(len(progress_calls), 0)

            # Check callback data structure
            if progress_calls:
                self.assertIn('line_number', progress_calls[0])
                self.assertIn('wordlist_path', progress_calls[0])
        finally:
            os.unlink(wordlist.name)


if __name__ == '__main__':
    unittest.main()
