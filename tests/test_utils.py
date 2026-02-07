"""
Unit tests for mask_parser, base_rules, rule_engine, and wordlist.
Covers rule application, mask expansion, rule parsing, and wordlist generation.
"""

import unittest
import tempfile
import os
from password_cracker.utils.mask_parser import parse_mask, BUILTIN_CHARSETS
from password_cracker.utils.mangling.base_rules import RULE_MAP
from password_cracker.utils.mangling.rule_engine import parse_rule, apply_rule, clean_and_extract_rule, load_rule_file
from password_cracker.utils.mangling.wordlist import read_wordlist, count_lines


class TestBaseRules(unittest.TestCase):
    """Test individual rule functions in base_rules.py"""

    def test_case_rules(self):
        self.assertEqual(RULE_MAP['c']("password"), "Password")
        self.assertEqual(RULE_MAP['u']("password"), "PASSWORD")
        self.assertEqual(RULE_MAP['l']("PASSWORD"), "password")
        self.assertEqual(RULE_MAP['T']("PaSsWoRd"), "pAsSwOrD")
        self.assertEqual(RULE_MAP['C']("password"), "pASSWORD")

    def test_addition_rules(self):
        self.assertEqual(RULE_MAP['^']("word", "!"), "!word")
        self.assertEqual(RULE_MAP['$']("word", "!"), "word!")

    def test_deletion_rules(self):
        self.assertEqual(RULE_MAP['[']("password"), "assword")
        self.assertEqual(RULE_MAP[']']("password"), "passwor")
        self.assertEqual(RULE_MAP['@']("banana", "a"), "bnn")

    def test_structural_rules(self):
        self.assertEqual(RULE_MAP['r']("abc"), "cba")
        self.assertEqual(RULE_MAP['{']("abc"), "bca")
        self.assertEqual(RULE_MAP['}']("abc"), "cab")
        self.assertEqual(RULE_MAP['d']("abc"), "abcabc")
        self.assertEqual(RULE_MAP['f']("abc"), "abccba")

    def test_positional_rules(self):
        self.assertEqual(RULE_MAP['s']("cat", "c", "h"), "hat")
        self.assertEqual(RULE_MAP['i']("abc", 1, "X"), "aXbc")
        self.assertEqual(RULE_MAP['o']("abc", 1, "X"), "aXc")
        self.assertEqual(RULE_MAP['*']("abc", 0, 2), "cba")
        self.assertEqual(RULE_MAP['+']("abc", 0), "bbc")
        self.assertEqual(RULE_MAP['-']("bbc", 0), "abc")
        self.assertEqual(RULE_MAP['D']("abc", 1), "ac")
        self.assertEqual(RULE_MAP["'"]("password", 4), "pass")
        self.assertEqual(RULE_MAP['t']("abc", 1), "aBc")


class TestMaskParser(unittest.TestCase):
    """Test mask parsing and charset expansion"""

    def test_builtin_masks(self):
        res = parse_mask("?u?l?d", {})
        self.assertEqual(res[0], ('variable', list(BUILTIN_CHARSETS['u'])))
        self.assertEqual(res[1], ('variable', list(BUILTIN_CHARSETS['l'])))
        self.assertEqual(res[2], ('variable', list(BUILTIN_CHARSETS['d'])))

    def test_fixed_chars(self):
        res = parse_mask("pass?d123", {})
        self.assertEqual(res[0], ('fixed', ['p']))
        self.assertEqual(res[4], ('variable', list(BUILTIN_CHARSETS['d'])))
        self.assertEqual(res[5], ('fixed', ['1']))

    def test_custom_charsets(self):
        custom = {'1': 'ABC'}
        res = parse_mask("?1", custom)
        self.assertEqual(res[0], ('variable', ['A', 'B', 'C']))

    def test_escaped_question_mark(self):
        res = parse_mask("??", {})
        self.assertEqual(res[0], ('fixed', ['?']))

    def test_invalid_masks(self):
        with self.assertRaises(ValueError):
            parse_mask("?z", {})
        with self.assertRaises(ValueError):
            parse_mask("password?", {})


class TestRuleEngine(unittest.TestCase):
    """Test the rule engine's ability to parse and apply complex strings"""

    def test_parse_position(self):
        from password_cracker.utils.mangling.rule_engine import parse_position
        self.assertEqual(parse_position('5'), 5)
        self.assertEqual(parse_position('A'), 10)
        self.assertEqual(parse_position('Z'), 35)

    def test_rule_parsing_valid(self):
        rules = parse_rule("c$1saz")
        self.assertEqual(rules[0], ('c', []))
        self.assertEqual(rules[1], ('$', ['1']))
        self.assertEqual(rules[2], ('s', ['a', 'z']))

    def test_rule_parsing_invalid(self):
        with self.assertRaises(ValueError):
            parse_rule("c$1!A")

    def test_apply_rule_chain(self):
        self.assertEqual(apply_rule("pass", "c$1"), "Pass1")
        self.assertEqual(apply_rule("abc", "ru"), "CBA")

    def test_clean_and_extract(self):
        # Your engine stops at the first space it hits after starting a rule
        self.assertEqual(clean_and_extract_rule("  c$1  "), "c$1")
        self.assertEqual(clean_and_extract_rule("c$1 # comment"), "c$1")
        self.assertEqual(clean_and_extract_rule("c $1"), "c")

    def test_load_rule_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write("c$1\n  u  \n# comment\n  r  # comment")
            tmp_path = tmp.name
        try:
            rules = load_rule_file(tmp_path)
            self.assertEqual(rules, ["c$1", "u", "r"])
        finally:
            os.unlink(tmp_path)


class TestWordlist(unittest.TestCase):
    """Test wordlist reading and counting utilities"""

    def setUp(self):
        self.content = "admin\npassword\n123456\n"
        self.tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.tmp.write(self.content)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_count_lines(self):
        self.assertEqual(count_lines(self.tmp.name), 3)

    def test_read_wordlist(self):
        words = list(read_wordlist(self.tmp.name))
        self.assertEqual(words, ["admin", "password", "123456"])

    def test_read_wordlist_with_start(self):
        words = list(read_wordlist(self.tmp.name, start_line=1))
        self.assertEqual(words, ["password", "123456"])

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(read_wordlist("non_existent.txt"))


if __name__ == '__main__':
    unittest.main()