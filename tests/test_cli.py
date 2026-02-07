"""
Unit tests for CLI module.
Tests command-line argument parsing, session management, and attack mode handling.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call, mock_open
import sys
import os
import json
import tempfile
import argparse
from io import StringIO

# Import the CLI class
from password_cracker.cli import CLI


class TestCLIInitialization(unittest.TestCase):
    """Test CLI initialization and setup"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    def test_cli_initialization(self):
        """Test that CLI initializes properly"""
        self.assertIsNotNone(self.cli)
        self.assertIsInstance(self.cli.parser, argparse.ArgumentParser)

    def test_attack_modes_defined(self):
        """Test that attack modes are properly defined"""
        expected_modes = {
            0: "Dictionary",
            1: "Combinator",
            2: "Brute-force/Mask",
            6: "Hybrid (Wordlist + Mask)",
            7: "Hybrid (Mask + Wordlist)",
            9: "Rules-based"
        }
        self.assertEqual(self.cli.ATTACK_MODES, expected_modes)

    def test_banner_generation(self):
        """Test that banner is generated"""
        banner = self.cli._get_banner()
        self.assertIsInstance(banner, str)
        self.assertIn("Password Cracker", banner)
        self.assertIn("Attack Modes", banner)

    def test_examples_generation(self):
        """Test that examples are generated"""
        examples = self.cli._get_examples()
        self.assertIsInstance(examples, str)
        self.assertIn("Examples:", examples)
        self.assertIn("cracker", examples)


class TestArgumentParsing(unittest.TestCase):
    """Test command-line argument parsing"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    def test_parse_dictionary_attack(self):
        """Test parsing dictionary attack arguments"""
        args = self.cli.parser.parse_args([
            '-a', '0',
            '-m', 'md5',
            '5f4dcc3b5aa765d61d8327deb882cf99',
            'wordlist.txt'
        ])

        self.assertEqual(args.attack_mode, 0)
        self.assertEqual(args.hash_type, 'md5')
        self.assertEqual(args.hash, '5f4dcc3b5aa765d61d8327deb882cf99')
        self.assertEqual(args.wordlist, 'wordlist.txt')

    def test_parse_combinator_attack(self):
        """Test parsing combinator attack arguments"""
        args = self.cli.parser.parse_args([
            '-a', '1',
            '-m', 'sha256',
            'somehash',
            'wordlist1.txt',
            'wordlist2.txt'
        ])

        self.assertEqual(args.attack_mode, 1)
        self.assertEqual(args.hash_type, 'sha256')
        self.assertEqual(args.wordlist, 'wordlist1.txt')
        self.assertEqual(args.wordlist2, 'wordlist2.txt')

    def test_parse_bruteforce_attack(self):
        """Test parsing brute-force attack arguments"""
        args = self.cli.parser.parse_args([
            '-a', '3',
            '-m', 'md5',
            'somehash',
            '-1', '?l?u'
        ])

        self.assertEqual(args.attack_mode, 3)
        self.assertEqual(args.custom_charset1, '?l?u')

    def test_parse_hybrid_attack_mode_6(self):
        """Test parsing hybrid attack mode 6 (wordlist + mask)"""
        args = self.cli.parser.parse_args([
            '-a', '6',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '?d?d?d'
        ])

        self.assertEqual(args.attack_mode, 6)
        self.assertEqual(args.wordlist, 'wordlist.txt')
        self.assertEqual(args.wordlist2, '?d?d?d')

    def test_parse_hybrid_attack_mode_7(self):
        """Test parsing hybrid attack mode 7 (mask + wordlist)"""
        args = self.cli.parser.parse_args([
            '-a', '7',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '?d?d?d'
        ])

        self.assertEqual(args.attack_mode, 7)

    def test_parse_rules_attack(self):
        """Test parsing rules attack arguments"""
        args = self.cli.parser.parse_args([
            '-a', '9',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '-r', 'rules/best64.rule',
            '-r', 'rules/custom.rule',
            '--rules-stack'
        ])

        self.assertEqual(args.attack_mode, 9)
        self.assertEqual(args.rules_file, ['rules/best64.rule', 'rules/custom.rule'])
        self.assertTrue(args.rules_stack)

    def test_parse_salt_options(self):
        """Test parsing salt options"""
        args = self.cli.parser.parse_args([
            '-a', '0',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '--salt', 'mysalt',
            '--hex-salt',
            '--salt-position', 'before'
        ])

        self.assertEqual(args.salt, 'mysalt')
        self.assertTrue(args.hex_salt)
        self.assertEqual(args.salt_position, 'before')

    def test_parse_session_options(self):
        """Test parsing session options"""
        args = self.cli.parser.parse_args([
            '-a', '0',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '--session', 'mysession'
        ])

        self.assertEqual(args.session, 'mysession')

    def test_parse_restore_option(self):
        """Test parsing restore option"""
        args = self.cli.parser.parse_args(['--restore', 'mysession'])
        self.assertEqual(args.restore, 'mysession')

    def test_parse_show_option(self):
        """Test parsing show option"""
        args = self.cli.parser.parse_args(['--show'])
        self.assertEqual(args.show, 'all')

    def test_parse_show_with_hash(self):
        """Test parsing show option with specific hash"""
        args = self.cli.parser.parse_args(['--show', 'somehash'])
        self.assertEqual(args.show, 'somehash')

    def test_parse_hash_info(self):
        """Test parsing hash-info option"""
        args = self.cli.parser.parse_args(['--hash-info', 'somehash'])
        self.assertEqual(args.hash_info, 'somehash')

    def test_parse_workers_option(self):
        """Test parsing workers option"""
        args = self.cli.parser.parse_args([
            '-a', '0',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '-w', '3'
        ])

        self.assertEqual(args.workers, 3)

    def test_parse_quiet_verbose_options(self):
        """Test parsing quiet and verbose options"""
        args_quiet = self.cli.parser.parse_args([
            '-a', '0',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '--quiet'
        ])
        self.assertTrue(args_quiet.quiet)

        args_verbose = self.cli.parser.parse_args([
            '-a', '0',
            '-m', 'md5',
            'somehash',
            'wordlist.txt',
            '--verbose'
        ])
        self.assertTrue(args_verbose.verbose)

    def test_parse_increment_options(self):
        """Test parsing increment options"""
        args = self.cli.parser.parse_args([
            '-a', '3',
            '-m', 'md5',
            'somehash',
            '--increment',
            '--increment-min', '4',
            '--increment-max', '8'
        ])

        self.assertTrue(args.increment)
        self.assertEqual(args.increment_min, 4)
        self.assertEqual(args.increment_max, 8)

    def test_parse_custom_charsets(self):
        """Test parsing custom charsets"""
        args = self.cli.parser.parse_args([
            '-a', '3',
            '-m', 'md5',
            'somehash',
            '-1', '?l?u',
            '-2', '?d',
            '-3', 'abc',
            '-4', 'xyz'
        ])

        self.assertEqual(args.custom_charset1, '?l?u')
        self.assertEqual(args.custom_charset2, '?d')
        self.assertEqual(args.custom_charset3, 'abc')
        self.assertEqual(args.custom_charset4, 'xyz')


class TestHashInfoUtility(unittest.TestCase):
    """Test hash info utility functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('password_cracker.cli.HashManager')
    def test_handle_hash_info(self, mock_hash_manager):
        """Test hash info display"""
        mock_hash_manager.repair_hash.return_value = '5f4dcc3b5aa765d61d8327deb882cf99'
        mock_hash_manager.identify_algorithms.return_value = ['MD5', 'NTLM']

        args = argparse.Namespace(hash_info='5f4dcc3b5aa765d61d8327deb882cf99')

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_hash_info(args)

        mock_hash_manager.identify_algorithms.assert_called_once()

    @patch('password_cracker.cli.HashManager')
    def test_handle_hash_info_no_candidates(self, mock_hash_manager):
        """Test hash info with no matching algorithms"""
        mock_hash_manager.repair_hash.return_value = 'invalid_hash'
        mock_hash_manager.identify_algorithms.return_value = []

        args = argparse.Namespace(hash_info='invalid_hash')

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_hash_info(args)
            output = mock_stdout.getvalue()
            self.assertIn('No matching', output)


class TestShowUtility(unittest.TestCase):
    """Test show utility functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='hash1:password1\nhash2:password2\n')
    def test_handle_show_all(self, mock_file, mock_exists):
        """Test showing all cracked passwords"""
        mock_exists.return_value = True

        args = argparse.Namespace(show='all', hash=None)

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_show(args)
            output = mock_stdout.getvalue()
            self.assertIn('password1', output)
            self.assertIn('password2', output)

    @patch('os.path.exists')
    @patch('password_cracker.cli.HashManager')
    @patch('builtins.open', new_callable=mock_open, read_data='5f4dcc3b5aa765d61d8327deb882cf99:password\n')
    def test_handle_show_specific(self, mock_file, mock_hash_manager, mock_exists):
        """Test showing specific cracked password"""
        mock_exists.return_value = True
        mock_hash_manager.repair_hash.return_value = '5f4dcc3b5aa765d61d8327deb882cf99'

        args = argparse.Namespace(
            show='5f4dcc3b5aa765d61d8327deb882cf99',
            hash=None
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_show(args)
            output = mock_stdout.getvalue()
            self.assertIn('password', output)

    @patch('os.path.exists')
    def test_handle_show_potfile_not_found(self, mock_exists):
        """Test showing when potfile doesn't exist"""
        mock_exists.return_value = False

        args = argparse.Namespace(show='all', hash=None)

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_show(args)
            output = mock_stdout.getvalue()
            self.assertIn('potfile', output.lower())


class TestSessionManagement(unittest.TestCase):
    """Test session management functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('builtins.input', return_value='y')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('password_cracker.cli.PasswordCracker')
    def test_handle_restore_dictionary(self, mock_cracker_class, mock_file, mock_exists, mock_input):
        """Test restoring a dictionary attack session"""
        mock_exists.return_value = True

        session_data = {
            'target_hash': '5f4dcc3b5aa765d61d8327deb882cf99',
            'algorithm': 'md5',
            'salt': '',
            'hex_salt': False,
            'salt_position': 'after',
            'strategy': 'dictionary',
            'progress': {
                'wordlist_path': 'wordlist.txt',
                'last_position': 100
            }
        }

        mock_file.return_value.read.return_value = json.dumps(session_data)

        mock_cracker = Mock()
        mock_cracker.dictionary.return_value = 'password'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            restore='mysession',
            quiet=True,
            workers=4,
            verbose=False,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_restore(args)

        mock_cracker_class.assert_called_once()
        call_kwargs = mock_cracker_class.call_args[1]
        self.assertEqual(call_kwargs['target_hash'], '5f4dcc3b5aa765d61d8327deb882cf99')
        self.assertEqual(call_kwargs['algorithm'], 'md5')
        mock_cracker.dictionary.assert_called_once()

    @patch('os.path.exists')
    def test_handle_restore_session_not_found(self, mock_exists):
        """Test restoring when session file doesn't exist"""
        mock_exists.return_value = False

        args = argparse.Namespace(
            restore='mysession',
            quiet=False,
            workers=4,
            verbose=False,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_restore(args)

    @patch('builtins.input', return_value='y')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('password_cracker.cli.PasswordCracker')
    def test_handle_restore_rules_attack(self, mock_cracker_class, mock_file, mock_exists, mock_input):
        """Test restoring a rules attack session"""
        mock_exists.return_value = True

        session_data = {
            'target_hash': 'somehash',
            'algorithm': 'sha256',
            'salt': '',
            'hex_salt': False,
            'salt_position': 'after',
            'strategy': 'rules',
            'progress': {
                'wordlist_path': 'wordlist.txt',
                'rules': ['rule1.rule', 'rule2.rule'],  # Changed from 'rules_files' to 'rules'
                'stack': True,
                'last_position': 50
            }
        }

        mock_file.return_value.read.return_value = json.dumps(session_data)

        mock_cracker = Mock()
        mock_cracker.rules.return_value = None
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            restore='mysession',
            quiet=True,
            workers=2,
            verbose=False,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_restore(args)

        mock_cracker.rules.assert_called_once()
        call_kwargs = mock_cracker.rules.call_args[1]
        self.assertEqual(call_kwargs['rules'], ['rule1.rule', 'rule2.rule'])
        self.assertTrue(call_kwargs['stack'])

    @patch('builtins.input', return_value='y')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('password_cracker.cli.PasswordCracker')
    def test_handle_restore_combinator_attack(self, mock_cracker_class, mock_file, mock_exists, mock_input):
        """Test restoring a combinator attack session"""
        mock_exists.return_value = True

        session_data = {
            'target_hash': 'somehash',
            'algorithm': 'md5',
            'salt': '',
            'hex_salt': False,
            'salt_position': 'after',
            'strategy': 'combinator',
            'progress': {
                'left_wordlist': 'left.txt',
                'right_wordlist': 'right.txt',
                'last_position': 200
            }
        }

        mock_file.return_value.read.return_value = json.dumps(session_data)

        mock_cracker = Mock()
        mock_cracker.combinator.return_value = 'cracked'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            restore='mysession',
            quiet=True,
            workers=4,
            verbose=False,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_restore(args)

        mock_cracker.combinator.assert_called_once()

    @patch('builtins.input', return_value='n')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_handle_restore_user_cancels(self, mock_file, mock_exists, mock_input):
        """Test restoring when user cancels"""
        mock_exists.return_value = True

        session_data = {
            'target_hash': 'somehash',
            'algorithm': 'md5',
            'salt': '',
            'hex_salt': False,
            'salt_position': 'after',
            'strategy': 'dictionary',
            'progress': {'wordlist_path': 'wordlist.txt'}
        }

        mock_file.return_value.read.return_value = json.dumps(session_data)

        args = argparse.Namespace(
            restore='mysession',
            quiet=False,
            workers=4,
            verbose=False,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_restore(args)

        # Should return early without creating cracker
        mock_input.assert_called_once()


class TestAttackExecution(unittest.TestCase):
    """Test attack execution methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_dictionary_success(self, mock_exists, mock_cracker_class):
        """Test successful dictionary attack"""
        mock_exists.return_value = True

        mock_cracker = Mock()
        mock_cracker.dictionary.return_value = 'password123'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=0,
            hash='5f4dcc3b5aa765d61d8327deb882cf99',
            hash_type='md5',
            wordlist='wordlist.txt',
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)

        mock_cracker.dictionary.assert_called_once_with(
            wordlist_path='wordlist.txt',
            processes=4
        )

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_dictionary_no_wordlist(self, mock_exists, mock_cracker_class):
        """Test dictionary attack without wordlist"""
        args = argparse.Namespace(
            attack_mode=0,
            hash='somehash',
            hash_type='md5',
            wordlist=None,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=False,
            workers=4,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_attack(args)

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_combinator(self, mock_exists, mock_cracker_class):
        """Test combinator attack"""
        mock_exists.return_value = True

        mock_cracker = Mock()
        mock_cracker.combinator.return_value = 'combined_pass'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=1,
            hash='somehash',
            hash_type='md5',
            wordlist='left.txt',
            wordlist2='right.txt',
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)
        mock_cracker.combinator.assert_called_once()

    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_bruteforce_with_mask(self, mock_cracker_class):
        """Test brute-force attack with mask"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = 'aaaa'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=3,
            hash='somehash',
            hash_type='md5',
            wordlist=None,
            wordlist2='?l?l?l?l',
            custom_charset1='?l?u',
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            increment=False,
            increment_min=1,
            increment_max=4,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)

        mock_cracker.brute_force.assert_called_once()
        call_kwargs = mock_cracker.brute_force.call_args[1]
        self.assertEqual(call_kwargs['mask'], '?l?l?l?l')

    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_bruteforce_increment(self, mock_cracker_class):
        """Test brute-force attack with increment mode"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = None
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=3,
            hash='somehash',
            hash_type='md5',
            wordlist=None,
            wordlist2=None,
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            increment=True,
            increment_min=4,
            increment_max=8,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)

        mock_cracker.brute_force.assert_called_once()
        call_kwargs = mock_cracker.brute_force.call_args[1]
        self.assertEqual(call_kwargs['min_length'], 4)
        self.assertEqual(call_kwargs['max_length'], 8)

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_hybrid_mode_6(self, mock_exists, mock_cracker_class):
        """Test hybrid attack mode 6 (wordlist + mask)"""
        mock_exists.return_value = True

        mock_cracker = Mock()
        mock_cracker.hybrid.return_value = 'word123'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=6,
            hash='somehash',
            hash_type='md5',
            wordlist='wordlist.txt',
            wordlist2='?d?d?d',
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)

        mock_cracker.hybrid.assert_called_once()
        call_kwargs = mock_cracker.hybrid.call_args[1]
        self.assertEqual(call_kwargs['position'], 'append')

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_hybrid_mode_7(self, mock_exists, mock_cracker_class):
        """Test hybrid attack mode 7 (mask + wordlist)"""
        mock_exists.return_value = True

        mock_cracker = Mock()
        mock_cracker.hybrid.return_value = '123word'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=7,
            hash='somehash',
            hash_type='md5',
            wordlist='wordlist.txt',
            wordlist2='?d?d?d',
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)

        mock_cracker.hybrid.assert_called_once()
        call_kwargs = mock_cracker.hybrid.call_args[1]
        self.assertEqual(call_kwargs['position'], 'prepend')

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_rules(self, mock_exists, mock_cracker_class):
        """Test rules attack"""
        mock_exists.return_value = True

        mock_cracker = Mock()
        mock_cracker.rules.return_value = 'P@ssw0rd'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=9,
            hash='somehash',
            hash_type='md5',
            wordlist='wordlist.txt',
            rules_file=['rule1.rule', 'rule2.rule'],
            rules_stack=True,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        self.cli._handle_attack(args)

        mock_cracker.rules.assert_called_once()
        call_kwargs = mock_cracker.rules.call_args[1]
        self.assertEqual(call_kwargs['rules'], ['rule1.rule', 'rule2.rule'])
        self.assertTrue(call_kwargs['stack'])

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_rules_no_wordlist(self, mock_exists, mock_cracker_class):
        """Test rules attack without wordlist"""
        args = argparse.Namespace(
            attack_mode=9,
            hash='somehash',
            hash_type='md5',
            wordlist=None,
            rules_file=['rule1.rule'],
            rules_stack=False,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=False,
            workers=4,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_attack(args)

    @patch('password_cracker.cli.PasswordCracker')
    @patch('os.path.exists')
    def test_attack_rules_no_rules_file(self, mock_exists, mock_cracker_class):
        """Test rules attack without rules file"""
        mock_exists.return_value = True

        args = argparse.Namespace(
            attack_mode=9,
            hash='somehash',
            hash_type='md5',
            wordlist='wordlist.txt',
            rules_file=None,
            rules_stack=False,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=False,
            workers=4,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_attack(args)


class TestPrintingMethods(unittest.TestCase):
    """Test output printing methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    def test_print_attack_header(self):
        """Test attack header printing"""
        args = argparse.Namespace(
            attack_mode=0,
            hash='5f4dcc3b5aa765d61d8327deb882cf99',
            hash_type='md5',
            salt='',
            workers=4
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._print_attack_header(args)
            output = mock_stdout.getvalue()
            self.assertIn('Dictionary', output)
            self.assertIn('5f4dcc3b5aa765d61d8327deb882cf99', output)

    def test_print_attack_header_with_salt(self):
        """Test attack header printing with salt"""
        args = argparse.Namespace(
            attack_mode=0,
            hash='somehash',
            hash_type='sha256',
            salt='mysalt',
            hex_salt=True,
            salt_position='before',
            workers=2
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._print_attack_header(args)
            output = mock_stdout.getvalue()
            self.assertIn('mysalt', output)
            self.assertIn('(hex)', output)

    def test_print_result_found(self):
        """Test result printing when password is found"""
        args = argparse.Namespace(hash='somehash')

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._print_result('password123', args)
            output = mock_stdout.getvalue()
            self.assertIn('PASSWORD FOUND', output)

    def test_print_result_not_found(self):
        """Test result printing when password is not found"""
        args = argparse.Namespace(hash='somehash')

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._print_result(None, args)
            output = mock_stdout.getvalue()
            self.assertIn('not found', output)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('os.path.exists')
    def test_attack_dictionary_wordlist_not_found(self, mock_exists):
        """Test dictionary attack when wordlist file doesn't exist"""
        mock_exists.return_value = False

        args = argparse.Namespace(
            attack_mode=0,
            hash='somehash',
            hash_type='md5',
            wordlist='nonexistent.txt',
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=False,
            workers=4,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_attack(args)

    @patch('os.path.exists')
    def test_attack_combinator_missing_wordlist(self, mock_exists):
        """Test combinator attack with missing wordlist"""
        args = argparse.Namespace(
            attack_mode=1,
            hash='somehash',
            hash_type='md5',
            wordlist='left.txt',
            wordlist2=None,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=False,
            workers=4,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_attack(args)

    @patch('password_cracker.cli.PasswordCracker')
    def test_quiet_mode_suppresses_output(self, mock_cracker_class):
        """Test that quiet mode suppresses output"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = 'pass'
        mock_cracker_class.return_value = mock_cracker

        args = argparse.Namespace(
            attack_mode=3,
            hash='somehash',
            hash_type='md5',
            wordlist=None,
            wordlist2='?l?l',
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            increment=False,
            increment_min=1,
            increment_max=4,
            salt='',
            hex_salt=False,
            salt_position='after',
            verbose=False,
            quiet=True,
            workers=4,
            checkpoint_interval=60
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_attack(args)
            output = mock_stdout.getvalue()
            self.assertEqual(output.strip(), '')


class TestRunMethod(unittest.TestCase):
    """Test the main run method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch.object(CLI, '_handle_hash_info')
    @patch('sys.argv', ['cracker', '--hash-info', 'somehash'])
    def test_run_hash_info(self, mock_handle):
        """Test run method with hash-info"""
        self.cli.run()
        mock_handle.assert_called_once()

    @patch.object(CLI, '_handle_show')
    @patch('sys.argv', ['cracker', '--show'])
    def test_run_show(self, mock_handle):
        """Test run method with show"""
        self.cli.run()
        mock_handle.assert_called_once()

    @patch.object(CLI, '_handle_restore')
    @patch('sys.argv', ['cracker', '--restore', 'mysession'])
    def test_run_restore(self, mock_handle):
        """Test run method with restore"""
        self.cli.run()
        mock_handle.assert_called_once()

    @patch.object(CLI, '_handle_attack')
    @patch('sys.argv', ['cracker', '-a', '0', '-m', 'md5', 'hash', 'wordlist.txt'])
    def test_run_attack(self, mock_handle):
        """Test run method with attack"""
        self.cli.run()
        mock_handle.assert_called_once()


if __name__ == '__main__':
    unittest.main()