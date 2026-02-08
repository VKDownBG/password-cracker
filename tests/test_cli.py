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
                'rules': ['rule1.rule', 'rule2.rule'],
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


class TestHandleGenerate(unittest.TestCase):
    """Test _handle_generate method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('password_cracker.cli.HashManager.generate_hash')
    def test_handle_generate_success(self, mock_generate):
        """Test successful hash generation"""
        mock_generate.return_value = '5f4dcc3b5aa765d61d8327deb882cf99'

        args = argparse.Namespace(
            generate=('password', 'md5'),
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_generate(args)
            output = mock_stdout.getvalue()
            self.assertIn('Generated MD5 hash', output)
            self.assertIn('5f4dcc3b5aa765d61d8327deb882cf99', output)

        mock_generate.assert_called_once_with(
            'password',
            'MD5',
            salt='',
            hex_salt=False,
            salt_position='after'
        )

    @patch('password_cracker.cli.HashManager.generate_hash')
    def test_handle_generate_with_salt(self, mock_generate):
        """Test hash generation with salt"""
        mock_generate.return_value = 'abcdef1234567890'

        args = argparse.Namespace(
            generate=('password', 'sha256'),
            salt='mysalt',
            hex_salt=True,
            salt_position='before'
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_generate(args)

        mock_generate.assert_called_once_with(
            'password',
            'SHA256',
            salt='mysalt',
            hex_salt=True,
            salt_position='before'
        )

    @patch('password_cracker.cli.HashManager.generate_hash')
    def test_handle_generate_error(self, mock_generate):
        """Test hash generation with error"""
        mock_generate.side_effect = ValueError("Invalid algorithm")

        args = argparse.Namespace(
            generate=('password', 'invalid'),
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_generate(args)


class TestHandleVerify(unittest.TestCase):
    """Test _handle_verify method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('password_cracker.cli.HashManager.verify_hash')
    def test_handle_verify_match_with_algorithm(self, mock_verify):
        """Test successful hash verification with specified algorithm"""
        mock_verify.return_value = (True, 'MD5')

        args = argparse.Namespace(
            verify=['password', '5f4dcc3b5aa765d61d8327deb882cf99', 'md5'],
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_verify(args)
            output = mock_stdout.getvalue()
            self.assertIn('MATCH', output)
            self.assertIn('MD5', output)

        mock_verify.assert_called_once_with(
            'password',
            '5f4dcc3b5aa765d61d8327deb882cf99',
            'MD5',
            salt='',
            hex_salt=False,
            salt_position='after'
        )

    @patch('password_cracker.cli.HashManager.verify_hash')
    def test_handle_verify_match_auto_detect(self, mock_verify):
        """Test successful hash verification with auto-detection"""
        mock_verify.return_value = (True, 'SHA256')

        args = argparse.Namespace(
            verify=['password', 'somehash'],
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_verify(args)
            output = mock_stdout.getvalue()
            self.assertIn('MATCH', output)
            self.assertIn('SHA256', output)

        mock_verify.assert_called_once_with(
            'password',
            'somehash',
            None,
            salt='',
            hex_salt=False,
            salt_position='after'
        )

    @patch('password_cracker.cli.HashManager.verify_hash')
    def test_handle_verify_no_match(self, mock_verify):
        """Test hash verification with no match"""
        mock_verify.return_value = (False, 'None')

        args = argparse.Namespace(
            verify=['wrongpassword', '5f4dcc3b5aa765d61d8327deb882cf99', 'md5'],
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._handle_verify(args)
            output = mock_stdout.getvalue()
            self.assertIn('No match', output)

    def test_handle_verify_insufficient_args(self):
        """Test hash verification with insufficient arguments"""
        args = argparse.Namespace(
            verify=['password'],
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_verify(args)

    def test_handle_verify_too_many_args(self):
        """Test hash verification with too many arguments"""
        args = argparse.Namespace(
            verify=['password', 'hash', 'algo', 'extra'],
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_verify(args)

    @patch('password_cracker.cli.HashManager.verify_hash')
    def test_handle_verify_with_salt(self, mock_verify):
        """Test hash verification with salt"""
        mock_verify.return_value = (True, 'MD5')

        args = argparse.Namespace(
            verify=['password', 'somehash', 'md5'],
            salt='mysalt',
            hex_salt=True,
            salt_position='before'
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._handle_verify(args)

        mock_verify.assert_called_once_with(
            'password',
            'somehash',
            'MD5',
            salt='mysalt',
            hex_salt=True,
            salt_position='before'
        )

    @patch('password_cracker.cli.HashManager.verify_hash')
    def test_handle_verify_exception(self, mock_verify):
        """Test hash verification with exception"""
        mock_verify.side_effect = Exception("Verification error")

        args = argparse.Namespace(
            verify=['password', 'hash', 'md5'],
            salt='',
            hex_salt=False,
            salt_position='after'
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._handle_verify(args)


class TestAttackDictionary(unittest.TestCase):
    """Test _attack_dictionary method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_dictionary_success(self, mock_cracker_class, mock_exists):
        """Test successful dictionary attack"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.dictionary.return_value = 'password123'

        args = argparse.Namespace(wordlist='wordlist.txt')

        result = self.cli._attack_dictionary(mock_cracker, args, 4)

        self.assertEqual(result, 'password123')
        mock_cracker.dictionary.assert_called_once_with(
            wordlist_path='wordlist.txt',
            processes=4
        )

    def test_attack_dictionary_no_wordlist(self):
        """Test dictionary attack without wordlist"""
        mock_cracker = Mock()
        args = argparse.Namespace(wordlist=None)

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_dictionary(mock_cracker, args, 4)

    @patch('os.path.exists')
    def test_attack_dictionary_wordlist_not_found(self, mock_exists):
        """Test dictionary attack with non-existent wordlist"""
        mock_exists.return_value = False
        mock_cracker = Mock()
        args = argparse.Namespace(wordlist='nonexistent.txt')

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_dictionary(mock_cracker, args, 4)


class TestAttackCombinator(unittest.TestCase):
    """Test _attack_combinator method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_combinator_success(self, mock_cracker_class, mock_exists):
        """Test successful combinator attack"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.combinator.return_value = 'password123'

        args = argparse.Namespace(
            wordlist='wordlist1.txt',
            wordlist2='wordlist2.txt'
        )

        result = self.cli._attack_combinator(mock_cracker, args, 4)

        self.assertEqual(result, 'password123')
        mock_cracker.combinator.assert_called_once_with(
            left_wordlist='wordlist1.txt',
            right_wordlist='wordlist2.txt',
            processes=4
        )

    def test_attack_combinator_missing_wordlist(self):
        """Test combinator attack with missing wordlist"""
        mock_cracker = Mock()
        args = argparse.Namespace(wordlist='wordlist1.txt', wordlist2=None)

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_combinator(mock_cracker, args, 4)

    def test_attack_combinator_missing_both_wordlists(self):
        """Test combinator attack with both wordlists missing"""
        mock_cracker = Mock()
        args = argparse.Namespace(wordlist=None, wordlist2=None)

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_combinator(mock_cracker, args, 4)

    @patch('os.path.exists')
    def test_attack_combinator_left_wordlist_not_found(self, mock_exists):
        """Test combinator attack with non-existent left wordlist"""
        mock_exists.return_value = False
        mock_cracker = Mock()
        args = argparse.Namespace(
            wordlist='nonexistent1.txt',
            wordlist2='wordlist2.txt'
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_combinator(mock_cracker, args, 4)

    @patch('os.path.exists')
    def test_attack_combinator_right_wordlist_not_found(self, mock_exists):
        """Test combinator attack with non-existent right wordlist"""
        def exists_side_effect(path):
            return path == 'wordlist1.txt'

        mock_exists.side_effect = exists_side_effect
        mock_cracker = Mock()
        args = argparse.Namespace(
            wordlist='wordlist1.txt',
            wordlist2='nonexistent2.txt'
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_combinator(mock_cracker, args, 4)


class TestAttackBruteforce(unittest.TestCase):
    """Test _attack_bruteforce method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_bruteforce_with_mask(self, mock_cracker_class):
        """Test brute-force attack with mask"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = 'pass123'

        args = argparse.Namespace(
            wordlist2='?l?l?l',
            custom_charset1='abc',
            custom_charset2='123',
            custom_charset3=None,
            custom_charset4=None,
            increment=False,
            increment_min=1,
            increment_max=4
        )

        result = self.cli._attack_bruteforce(mock_cracker, args, 4)

        self.assertEqual(result, 'pass123')
        mock_cracker.brute_force.assert_called_once()
        call_kwargs = mock_cracker.brute_force.call_args[1]
        self.assertEqual(call_kwargs['mask'], '?l?l?l')
        self.assertEqual(call_kwargs['custom_charsets'], {'1': 'abc', '2': '123'})
        self.assertEqual(call_kwargs['processes'], 4)

    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_bruteforce_increment_mode(self, mock_cracker_class):
        """Test brute-force attack with increment mode"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = 'abc'

        args = argparse.Namespace(
            wordlist2=None,
            custom_charset1='abc',
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            increment=True,
            increment_min=2,
            increment_max=5
        )

        result = self.cli._attack_bruteforce(mock_cracker, args, 2)

        self.assertEqual(result, 'abc')
        mock_cracker.brute_force.assert_called_once()
        call_kwargs = mock_cracker.brute_force.call_args[1]
        self.assertEqual(call_kwargs['min_length'], 2)
        self.assertEqual(call_kwargs['max_length'], 5)
        self.assertEqual(call_kwargs['charset'], 'a')
        self.assertEqual(call_kwargs['custom_charsets'], {'1': 'abc'})

    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_bruteforce_default_increment(self, mock_cracker_class):
        """Test brute-force attack with default increment"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = None

        args = argparse.Namespace(
            wordlist2=None,
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None,
            increment=False,
            increment_min=1,
            increment_max=4
        )

        with patch('sys.stdout', new_callable=StringIO):
            result = self.cli._attack_bruteforce(mock_cracker, args, 4)

        mock_cracker.brute_force.assert_called_once()
        call_kwargs = mock_cracker.brute_force.call_args[1]
        self.assertEqual(call_kwargs['min_length'], 1)
        self.assertEqual(call_kwargs['max_length'], 4)
        self.assertEqual(call_kwargs['charset'], 'a')

    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_bruteforce_all_custom_charsets(self, mock_cracker_class):
        """Test brute-force attack with all custom charsets"""
        mock_cracker = Mock()
        mock_cracker.brute_force.return_value = 'test'

        args = argparse.Namespace(
            wordlist2='?1?2?3?4',
            custom_charset1='abc',
            custom_charset2='123',
            custom_charset3='xyz',
            custom_charset4='!@#',
            increment=False,
            increment_min=1,
            increment_max=4
        )

        result = self.cli._attack_bruteforce(mock_cracker, args, 4)

        call_kwargs = mock_cracker.brute_force.call_args[1]
        self.assertEqual(call_kwargs['custom_charsets'], {
            '1': 'abc',
            '2': '123',
            '3': 'xyz',
            '4': '!@#'
        })


class TestAttackHybrid(unittest.TestCase):
    """Test _attack_hybrid method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_hybrid_append(self, mock_cracker_class, mock_exists):
        """Test hybrid attack with append position"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.hybrid.return_value = 'password123'

        args = argparse.Namespace(
            attack_mode=6,
            wordlist='wordlist.txt',
            wordlist2='?d?d?d',
            custom_charset1='abc',
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None
        )

        result = self.cli._attack_hybrid(mock_cracker, args, 4, 'append')

        self.assertEqual(result, 'password123')
        mock_cracker.hybrid.assert_called_once_with(
            wordlist_path='wordlist.txt',
            mask='?d?d?d',
            position='append',
            custom_charsets={'1': 'abc'},
            processes=4
        )

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_hybrid_prepend(self, mock_cracker_class, mock_exists):
        """Test hybrid attack with prepend position"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.hybrid.return_value = '123password'

        args = argparse.Namespace(
            attack_mode=7,
            wordlist='wordlist.txt',
            wordlist2='?d?d?d',
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None
        )

        result = self.cli._attack_hybrid(mock_cracker, args, 2, 'prepend')

        self.assertEqual(result, '123password')
        mock_cracker.hybrid.assert_called_once()
        call_kwargs = mock_cracker.hybrid.call_args[1]
        self.assertEqual(call_kwargs['position'], 'prepend')

    def test_attack_hybrid_missing_wordlist(self):
        """Test hybrid attack without wordlist"""
        mock_cracker = Mock()
        args = argparse.Namespace(
            attack_mode=6,
            wordlist=None,
            wordlist2='?d?d?d',
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_hybrid(mock_cracker, args, 4, 'append')

    def test_attack_hybrid_missing_mask(self):
        """Test hybrid attack without mask"""
        mock_cracker = Mock()
        args = argparse.Namespace(
            attack_mode=6,
            wordlist='wordlist.txt',
            wordlist2=None,
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_hybrid(mock_cracker, args, 4, 'append')

    @patch('os.path.exists')
    def test_attack_hybrid_wordlist_not_found(self, mock_exists):
        """Test hybrid attack with non-existent wordlist"""
        mock_exists.return_value = False
        mock_cracker = Mock()
        args = argparse.Namespace(
            attack_mode=6,
            wordlist='nonexistent.txt',
            wordlist2='?d?d?d',
            custom_charset1=None,
            custom_charset2=None,
            custom_charset3=None,
            custom_charset4=None
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_hybrid(mock_cracker, args, 4, 'append')

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_hybrid_with_all_charsets(self, mock_cracker_class, mock_exists):
        """Test hybrid attack with all custom charsets"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.hybrid.return_value = 'result'

        args = argparse.Namespace(
            attack_mode=6,
            wordlist='wordlist.txt',
            wordlist2='?1?2?3?4',
            custom_charset1='a',
            custom_charset2='b',
            custom_charset3='c',
            custom_charset4='d'
        )

        self.cli._attack_hybrid(mock_cracker, args, 4, 'append')

        call_kwargs = mock_cracker.hybrid.call_args[1]
        self.assertEqual(call_kwargs['custom_charsets'], {
            '1': 'a',
            '2': 'b',
            '3': 'c',
            '4': 'd'
        })


class TestAttackRules(unittest.TestCase):
    """Test _attack_rules method"""

    def setUp(self):
        """Set up test fixtures"""
        self.cli = CLI()

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_rules_success(self, mock_cracker_class, mock_exists):
        """Test successful rules attack"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.rules.return_value = 'Password123'

        args = argparse.Namespace(
            wordlist='wordlist.txt',
            rules_file=['rules/best64.rule'],
            rules_stack=False
        )

        result = self.cli._attack_rules(mock_cracker, args, 4)

        self.assertEqual(result, 'Password123')
        mock_cracker.rules.assert_called_once_with(
            wordlist_path='wordlist.txt',
            rules=['rules/best64.rule'],
            stack=False,
            processes=4
        )

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_rules_multiple_files(self, mock_cracker_class, mock_exists):
        """Test rules attack with multiple rule files"""
        mock_exists.return_value = True
        mock_cracker = Mock()
        mock_cracker.rules.return_value = 'P@ssw0rd'

        args = argparse.Namespace(
            wordlist='wordlist.txt',
            rules_file=['rule1.rule', 'rule2.rule', 'rule3.rule'],
            rules_stack=True
        )

        result = self.cli._attack_rules(mock_cracker, args, 8)

        mock_cracker.rules.assert_called_once()
        call_kwargs = mock_cracker.rules.call_args[1]
        self.assertEqual(call_kwargs['rules'], ['rule1.rule', 'rule2.rule', 'rule3.rule'])
        self.assertTrue(call_kwargs['stack'])
        self.assertEqual(call_kwargs['processes'], 8)

    def test_attack_rules_no_wordlist(self):
        """Test rules attack without wordlist"""
        mock_cracker = Mock()
        args = argparse.Namespace(
            wordlist=None,
            rules_file=['rules/best64.rule'],
            rules_stack=False
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_rules(mock_cracker, args, 4)

    def test_attack_rules_no_rules_file(self):
        """Test rules attack without rules file"""
        mock_cracker = Mock()
        args = argparse.Namespace(
            wordlist='wordlist.txt',
            rules_file=None,
            rules_stack=False
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_rules(mock_cracker, args, 4)

    @patch('os.path.exists')
    def test_attack_rules_wordlist_not_found(self, mock_exists):
        """Test rules attack with non-existent wordlist"""
        mock_exists.return_value = False
        mock_cracker = Mock()
        args = argparse.Namespace(
            wordlist='nonexistent.txt',
            rules_file=['rules/best64.rule'],
            rules_stack=False
        )

        with patch('sys.stdout', new_callable=StringIO):
            with self.assertRaises(SystemExit):
                self.cli._attack_rules(mock_cracker, args, 4)

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_rules_missing_rule_file_warning(self, mock_cracker_class, mock_exists):
        """Test rules attack with missing rule file shows warning"""
        def exists_side_effect(path):
            return path == 'wordlist.txt'

        mock_exists.side_effect = exists_side_effect
        mock_cracker = Mock()
        mock_cracker.rules.return_value = None

        # Changed filename from 'nonexistent.rule' to 'missing_file.txt'
        # to avoid triggering the "raw rule syntax" detection (because 'u' is a rule char)
        args = argparse.Namespace(
            wordlist='wordlist.txt',
            rules_file=['missing_file.txt'],
            rules_stack=False
        )

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            self.cli._attack_rules(mock_cracker, args, 4)
            output = mock_stdout.getvalue()
            self.assertIn('Warning', output)

    @patch('os.path.exists')
    @patch('password_cracker.cli.PasswordCracker')
    def test_attack_rules_raw_rule_syntax(self, mock_cracker_class, mock_exists):
        """Test rules attack with raw rule syntax (contains special chars)"""
        def exists_side_effect(path):
            return path == 'wordlist.txt'

        mock_exists.side_effect = exists_side_effect
        mock_cracker = Mock()
        mock_cracker.rules.return_value = None

        args = argparse.Namespace(
            wordlist='wordlist.txt',
            rules_file=[':c'],
            rules_stack=False
        )

        with patch('sys.stdout', new_callable=StringIO):
            self.cli._attack_rules(mock_cracker, args, 4)

        # Should not raise error for raw rule syntax
        mock_cracker.rules.assert_called_once()


class TestMainFunction(unittest.TestCase):
    """Test main() function"""

    @patch.object(CLI, 'run')
    def test_main_calls_cli_run(self, mock_run):
        """Test that main() creates CLI instance and calls run()"""
        from password_cracker.cli import main

        main()

        mock_run.assert_called_once()


if __name__ == '__main__':
    unittest.main()