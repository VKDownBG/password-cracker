import argparse
import sys
import os
import json
from typing import Optional
from argparse import Namespace, RawDescriptionHelpFormatter

from .core.hasher import HashManager
from .core.cracker import PasswordCracker


class CLI:
    ATTACK_MODES = {
        0: "Dictionary",
        1: "Combinator",
        2: "Brute-force/Mask",
        6: "Hybrid (Wordlist + Mask)",
        7: "Hybrid (Mask + Wordlist)",
        9: "Rules-based"
    }

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog="cracker",
            description=self._get_banner(),
            formatter_class=RawDescriptionHelpFormatter,
            epilog=self._get_examples()
        )

        self._setup_arguments()

    def _get_banner(self) -> str:
        return """
        ╔═══════════════════════════════════════════════════════════╗
        ║           Password Cracker - Hash Analysis Tool           ║
        ╚═══════════════════════════════════════════════════════════╝

        Attack Modes:
          -a 0   Dictionary attack
          -a 1   Combinator attack  
          -a 3   Brute-force / Mask attack
          -a 6   Hybrid (Wordlist + Mask)
          -a 7   Hybrid (Mask + Wordlist)
          -a 9   Rules-based attack
        """

    def _get_examples(self) -> str:
        return """
        Examples:
          # Hash utilities
          cracker --hash-info <hash>                    Identify hash algorithm
          cracker --show                                Show all cracked passwords
          cracker --show <hash>                         Show specific cracked password

          # Dictionary attack
          cracker -a 0 -m md5 <hash> wordlist.txt

          # Dictionary with rules
          cracker -a 9 -m md5 <hash> wordlist.txt -r rules/best64.rule
          cracker -a 9 -m md5 <hash> wordlist.txt -r rule1.rule -r rule2.rule --rules-stack

          # Brute-force with mask
          cracker -a 3 -m md5 <hash> -1 ?l?u ?1?1?1?1?1?1
          cracker -a 3 -m md5 <hash> --increment --increment-min 4 --increment-max 8

          # Hybrid attacks
          cracker -a 6 -m md5 <hash> wordlist.txt ?d?d?d
          cracker -a 7 -m md5 <hash> ?d?d?d wordlist.txt

          # Combinator attack
          cracker -a 1 -m md5 <hash> wordlist1.txt wordlist2.txt

          # With salt
          cracker -a 0 -m md5 <hash> wordlist.txt --salt mysalt
          cracker -a 0 -m md5 <hash> wordlist.txt --hex-salt --salt-position before

          # Session management
          cracker -a 0 -m md5 <hash> wordlist.txt --session mysession
          cracker --restore mysession

          # Performance tuning
          cracker -a 0 -m md5 <hash> wordlist.txt -w 3
        """

    def _setup_arguments(self):
        # ============================================
        # MAIN OPERATIONS
        # ============================================

        main_group = self.parser.add_argument_group('Main Operations')

        main_group.add_argument(
            'hash',
            nargs='?',
            help='Target hash to crack'
        )

        main_group.add_argument(
            'wordlist',
            nargs='?',
            help='Path to wordlist file (or first wordlist for combinator)'
        )

        main_group.add_argument(
            'wordlist2',
            nargs='?',
            help='Second wordlist (for combinator) or mask (for brute-force/hybrid)'
        )

        # ============================================
        # ATTACK CONFIGURATION
        # ============================================

        attack_group = self.parser.add_argument_group('Attack Configuration')

        attack_group.add_argument(
            '-a', '--attack-mode',
            type=int,
            choices=[0, 1, 3, 6, 7, 9],
            metavar='NUM',
            help='Attack mode: 0=Dictionary, 1=Combinator, 3=Brute-force, 6=Hybrid(W+M), 7=Hybrid(M+W), 9=Rules'
        )

        attack_group.add_argument(
            '-m', '--hash-type',
            type=str,
            metavar='TYPE',
            help='Hash type (e.g., md5, sha256, sha512). Leave empty for auto-detect'
        )

        # ============================================
        # BRUTE-FORCE / MASK OPTIONS
        # ============================================

        mask_group = self.parser.add_argument_group('Mask Attack Options')

        mask_group.add_argument(
            '-1', '--custom-charset1',
            type=str,
            metavar='CS',
            help='Custom charset 1'
        )

        mask_group.add_argument(
            '-2', '--custom-charset2',
            type=str,
            metavar='CS',
            help='Custom charset 2'
        )

        mask_group.add_argument(
            '-3', '--custom-charset3',
            type=str,
            metavar='CS',
            help='Custom charset 3'
        )

        mask_group.add_argument(
            '-4', '--custom-charset4',
            type=str,
            metavar='CS',
            help='Custom charset 4'
        )

        mask_group.add_argument(
            '--increment',
            action='store_true',
            help='Enable mask increment mode'
        )

        mask_group.add_argument(
            '--increment-min',
            type=int,
            default=1,
            metavar='NUM',
            help='Start increment at NUM (default: 1)'
        )

        mask_group.add_argument(
            '--increment-max',
            type=int,
            default=4,
            metavar='NUM',
            help='Stop increment at NUM (default: 4)'
        )

        # ============================================
        # RULES OPTIONS
        # ============================================

        rules_group = self.parser.add_argument_group('Rules Attack Options')

        rules_group.add_argument(
            '-r', '--rules-file',
            action='append',
            metavar='FILE',
            help='Rules file (can be specified multiple times)'
        )

        rules_group.add_argument(
            '--rules-stack',
            action='store_true',
            help='Stack multiple rules (apply sequentially)'
        )

        # ============================================
        # SALT OPTIONS
        # ============================================

        salt_group = self.parser.add_argument_group('Salt Options')

        salt_group.add_argument(
            '--salt',
            type=str,
            default='',
            metavar='SALT',
            help='Salt value to use'
        )

        salt_group.add_argument(
            '--hex-salt',
            action='store_true',
            help='Treat salt as hexadecimal'
        )

        salt_group.add_argument(
            '--salt-position',
            choices=['before', 'after'],
            default='after',
            metavar='POS',
            help='Salt position: before or after the password (default: after)'
        )

        # ============================================
        # SESSION MANAGEMENT
        # ============================================

        session_group = self.parser.add_argument_group('Session Management')

        session_group.add_argument(
            '--session',
            type=str,
            metavar='NAME',
            help='Session name for checkpointing'
        )

        session_group.add_argument(
            '--restore',
            type=str,
            metavar='NAME',
            help='Restore session by name'
        )

        session_group.add_argument(
            '--checkpoint-interval',
            type=int,
            default=60,
            metavar='SEC',
            help='Checkpoint interval in seconds (default: 60)'
        )

        # ============================================
        # POTFILE MANAGEMENT
        # ============================================

        potfile_group = self.parser.add_argument_group('Potfile Management')

        potfile_group.add_argument(
            '--show',
            nargs='?',
            const='all',
            metavar='HASH',
            help='Show all cracked passwords (or specific hash)'
        )

        potfile_group.add_argument(
            '--potfile-disable',
            action='store_true',
            help='Do not write results to potfile'
        )

        potfile_group.add_argument(
            '--potfile-path',
            type=str,
            metavar='PATH',
            help='Custom potfile path'
        )

        # ============================================
        # HASH UTILITIES
        # ============================================

        utils_group = self.parser.add_argument_group('Hash Utilities')

        utils_group.add_argument(
            '--hash-info',
            type=str,
            metavar='HASH',
            help='Identify hash algorithm'
        )

        utils_group.add_argument(
            '--generate',
            nargs=2,
            metavar=('TEXT', 'ALGO'),
            help='Generate hash from text'
        )

        utils_group.add_argument(
            '--verify',
            nargs='+',
            metavar='ARG',
            help='Verify text against hash: TEXT HASH [ALGO] (algorithm is optional for auto-detect)'
        )

        # ============================================
        # PERFORMANCE & OUTPUT
        # ============================================

        perf_group = self.parser.add_argument_group('Performance & Output')

        perf_group.add_argument(
            '-w', '--workers',
            type=int,
            default=4,
            metavar='NUM',
            help='Number of parallel worker processes (default: 4)'
        )

        perf_group.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

        perf_group.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress all output except results'
        )

    def run(self):
        args = self.parser.parse_args()

        try:
            if args.hash_info:
                self._handle_hash_info(args)
                return

            if args.generate:
                self._handle_generate(args)
                return

            if args.verify:
                self._handle_verify(args)
                return

            if args.show:
                self._handle_show(args)
                return

            if args.restore:
                self._handle_restore(args)
                return

            if args.attack_mode is None:
                self.parser.print_help()
                print("\n[!] Error: Attack mode (-a) is required for cracking operations")
                sys.exit(1)

            if not args.hash:
                print("[!] Error: Target hash is required")
                sys.exit(1)

            self._handle_attack(args)

        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            sys.exit(130)
        except Exception as e:
            if args.verbose:
                import traceback
                traceback.print_exc()
            print(f"\n[!] Error: {str(e)}")
            sys.exit(1)

    def _handle_hash_info(self, args: Namespace) -> None:
        target_hash = HashManager.repair_hash(args.hash_info)

        if not target_hash:
            print("[!] Error: Invalid hash provided")
            return

        print(f"\n[*] Analyzing hash: {target_hash}")
        print(f"[*] Length: {len(target_hash)} characters\n")

        candidates = HashManager.identify_algorithms(target_hash)

        if not candidates:
            print("[-] Error: No matching algorithms found for this length/format.")
            return

        print(f"[+] Possible algorithms ({len(candidates)}):\n")
        for i, algo in enumerate(candidates, 1):
            print(f"  {i:2d}. {algo}")

        print("\n[*] Use -m <algorithm> to specify hash type")

    def _handle_generate(self, args: Namespace) -> None:
        text, algorithm = args.generate

        try:
            result = HashManager.generate_hash(
                text,
                algorithm.upper(),
                salt=args.salt,
                hex_salt=args.hex_salt,
                salt_position=args.salt_position
            )

            print(f"\n[+] Generated {algorithm.upper()} hash:")
            print(f"{result}")

        except ValueError as e:
            print(f"[!] Error: {str(e)}")
            sys.exit(1)

    def _handle_verify(self, args: Namespace) -> None:
        if len(args.verify) < 2 or len(args.verify) > 3:
            print("[!] Error: --verify requires 2 or 3 arguments: TEXT HASH [ALGO]")
            sys.exit(1)

        text = args.verify[0]
        target_hash = args.verify[1]
        algorithm = args.verify[2].upper() if len(args.verify) == 3 else None

        try:
            is_match, found_algorithm = HashManager.verify_hash(
                text,
                target_hash,
                algorithm.upper() if algorithm else None,
                salt=args.salt,
                hex_salt=args.hex_salt,
                salt_position=args.salt_position
            )

            if is_match:
                print(f"\n[+] MATCH! Hash verified successfully")
                print(f"[+] Algorithm: {found_algorithm}")
            else:
                print(f"\n[-] No match found")

        except Exception as e:
            print(f"[!] Error: {str(e)}")
            sys.exit(1)

    def _handle_show(self, args: Namespace) -> None:
        current_dir = os.path.dirname(os.path.abspath(__file__))

        root_dir = os.path.dirname(current_dir)
        potfile_path = os.path.join(root_dir, "cache", "cracked.potfile")

        if not os.path.exists(potfile_path):
            print("[!] No potfile found")
            return

        try:
            with open(potfile_path, 'r', encoding='utf-8-sig') as f:
                lines = f.readlines()

            if not lines:
                print("[*] Potfile is empty")
                return

            if args.show != 'all':
                target = HashManager.repair_hash(args.show)
                lines = [line for line in lines if line.startswith(target + ':')]

                if not lines:
                    print(f"[!] Hash not found in potfile: {target}")
                    return

            print(f"\n[+] Cracked passwords ({len(lines)}):\n")
            print(f"{'Hash':<64} Password")
            print("=" * 100)

            for line in lines:
                line = line.strip()
                if ':' in line:
                    hash_val, password = line.split(':', 1)
                    print(f"{hash_val:<64} {password}")

        except Exception as e:
            print(f"[!] Error reading potfile: {str(e)}")
            sys.exit(1)

    def _handle_restore(self, args: Namespace) -> None:
        print(f"\n[*] Restoring session '{args.restore}'")

        cache_folder = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        cache_path = os.path.join(cache_folder, "cache")
        session_file = os.path.join(cache_path, f"{args.restore}.json")

        if not os.path.exists(session_file):
            print(f"[!] Error: Session file not found: {session_file}")
            print(f"[!] No session named '{args.restore}' exists")
            sys.exit(1)

        try:
            with open(session_file, 'r', encoding='utf-8-sig') as f:
                session = json.load(f)
        except Exception as e:
            print(f"[!] Error loading session file: {str(e)}")
            sys.exit(1)

        target_hash = session.get('target_hash')
        algorithm = session.get('algorithm')
        salt = session.get('salt', '')
        hex_salt = session.get('hex_salt', False)
        salt_position = session.get('salt_position', 'after')
        strategy = session.get('strategy')
        progress = session.get('progress', {})

        print(f"\n[*] Session found!")
        print(f"    Strategy:      {strategy}")
        print(f"    Target Hash:   {target_hash}")
        print(f"    Algorithm:     {algorithm if algorithm else 'Auto-detect'}")
        print(f"    Started:       {session.get('started_at')}")
        print(f"    Last Saved:    {session.get('last_save')}")

        if progress:
            print(f"    Progress:      {json.dumps(progress, indent=19)}")

        response = input("\n[?] Continue this session? [Y/n]: ").strip().lower()
        if response in ['n', 'no']:
            print("[*] Restore cancelled")
            return

        print("\n" + "=" * 60)
        print(f"Restoring: {strategy} attack")
        print("=" * 60 + "\n")

        cracker = PasswordCracker(
            target_hash=target_hash,
            algorithm=algorithm,
            salt=salt,
            hex_salt=hex_salt,
            salt_position=salt_position,
            verbose=args.verbose and not args.quiet,
            checkpoint_interval=args.checkpoint_interval
        )

        result = None
        processes = args.workers

        try:
            if strategy == 'dictionary':
                wordlist_path = progress.get('wordlist_path', '')
                if not wordlist_path:
                    print("[!] Error: Wordlist path not found in session")
                    sys.exit(1)
                result = cracker.dictionary(wordlist_path=wordlist_path, processes=processes)

            elif strategy == 'rules':
                wordlist_path = progress.get('wordlist_path', '')
                rules = progress.get('rules', [])
                stack = progress.get('stack', False)
                if not wordlist_path or not rules:
                    print("[!] Error: Rules attack parameters not found in session")
                    sys.exit(1)
                result = cracker.rules(wordlist_path=wordlist_path, rules=rules, stack=stack, processes=processes)

            elif strategy == 'brute_force':
                mode = progress.get('mode', 'incremental')

                if mode == 'mask':
                    mask = progress.get('mask')
                    custom_charsets = progress.get('custom_charsets', {})

                    if not mask:
                        print("[!] Error: Mask not found in session")
                        sys.exit(1)

                    result = cracker.brute_force(
                        mask=mask,
                        custom_charsets=custom_charsets,
                        processes=processes
                    )
                else:
                    min_length = progress.get('min_length', 1)
                    max_length = progress.get('max_length', 4)
                    charset = progress.get('charset', 'a')
                    custom_charsets = progress.get('custom_charsets', {})

                    result = cracker.brute_force(
                        mask=None,
                        min_length=min_length,
                        max_length=max_length,
                        charset=charset,
                        custom_charsets=custom_charsets,
                        processes=processes
                    )

            elif strategy == 'hybrid':
                wordlist_path = progress.get('wordlist_path', '')
                mask = progress.get('mask', '')
                position = progress.get('position', 'append')
                custom_charsets = progress.get('custom_charsets', {})

                if not wordlist_path or not mask:
                    print("[!] Error: Hybrid attack parameters not found in session")
                    sys.exit(1)

                result = cracker.hybrid(
                    wordlist_path=wordlist_path,
                    mask=mask,
                    position=position,
                    custom_charsets=custom_charsets,
                    processes=processes
                )

            elif strategy == 'combinator':
                left_wordlist = progress.get('left_wordlist', '')
                right_wordlist = progress.get('right_wordlist', '')

                if not left_wordlist or not right_wordlist:
                    print("[!] Error: Combinator attack parameters not found in session")
                    sys.exit(1)

                result = cracker.combinator(
                    left_wordlist=left_wordlist,
                    right_wordlist=right_wordlist,
                    processes=processes
                )

            else:
                print(f"[!] Error: Unknown strategy '{strategy}'")
                sys.exit(1)

            if not args.quiet:
                print("\n" + "=" * 60)
                if result:
                    print("[+] PASSWORD FOUND!")
                    print("=" * 60)
                    print(f"\nHash:     {target_hash}")
                    print(f"Password: {result}\n")
                else:
                    print("[-] Password not found")
                    print("=" * 60 + "\n")

        except KeyboardInterrupt:
            print("\n\n[!] Session interrupted - progress saved")
            sys.exit(130)

    def _handle_attack(self, args: Namespace) -> None:
        processes = args.workers

        if not args.quiet:
            self._print_attack_header(args)

        cracker = PasswordCracker(
            target_hash=args.hash,
            algorithm=args.hash_type if args.hash_type else None,
            salt=args.salt,
            hex_salt=args.hex_salt,
            salt_position=args.salt_position,
            verbose=args.verbose and not args.quiet,
            checkpoint_interval=args.checkpoint_interval
        )

        result = None

        if args.attack_mode == 0:
            result = self._attack_dictionary(cracker, args, processes)
        elif args.attack_mode == 1:
            result = self._attack_combinator(cracker, args, processes)
        elif args.attack_mode == 3:
            result = self._attack_bruteforce(cracker, args, processes)
        elif args.attack_mode == 6:
            result = self._attack_hybrid(cracker, args, processes, position='append')
        elif args.attack_mode == 7:
            result = self._attack_hybrid(cracker, args, processes, position='prepend')
        elif args.attack_mode == 9:
            result = self._attack_rules(cracker, args, processes)

        if not args.quiet:
            self._print_result(result, args)

    def _print_attack_header(self, args: Namespace):
        print("\n" + "=" * 60)
        print(f"Attack Mode: {self.ATTACK_MODES.get(args.attack_mode, 'Unknown')}")
        print(f"Target Hash: {args.hash}")

        if args.hash_type:
            print(f"Hash Type:   {args.hash_type.upper()}")
        else:
            print(f"Hash Type:   Auto-detect")

        if args.salt:
            print(f"Salt:        {args.salt} {'(hex)' if args.hex_salt else ''}")
            print(f"Position:    {args.salt_position}")

        print(f"Workers:     {args.workers}")
        print("=" * 60 + "\n")

    def _print_result(self, result: Optional[str], args: Namespace) -> None:
        print("\n" + "=" * 60)

        if result:
            print("[+] PASSWORD FOUND!")
            print("=" * 60)
            print(f"\nHash:     {args.hash}")
            print(f"Password: {result}\n")
        else:
            print("[-] Password not found")
            print("=" * 60 + "\n")

    def _attack_dictionary(self, cracker: PasswordCracker, args: Namespace, processes: int) -> Optional[str]:
        if not args.wordlist:
            print("[!] Error: Wordlist required for dictionary attack")
            sys.exit(1)

        if not os.path.exists(args.wordlist):
            print(f"[!] Error: Wordlist not found: {args.wordlist}")
            sys.exit(1)

        return cracker.dictionary(
            wordlist_path=args.wordlist,
            processes=processes
        )

    def _attack_combinator(self, cracker: PasswordCracker, args: Namespace, processes: int) -> Optional[str]:
        if not args.wordlist or not args.wordlist2:
            print("[!] Error: Two wordlists required for combinator attack")
            print("[!] Usage: -a 1 <hash> <wordlist1> <wordlist2>")
            sys.exit(1)

        left_wordlist = args.wordlist
        right_wordlist = args.wordlist2

        if not os.path.exists(left_wordlist):
            print(f"[!] Error: Wordlist not found: {left_wordlist}")
            sys.exit(1)

        if not os.path.exists(right_wordlist):
            print(f"[!] Error: Wordlist not found: {right_wordlist}")
            sys.exit(1)

        return cracker.combinator(
            left_wordlist=left_wordlist,
            right_wordlist=right_wordlist,
            processes=processes
        )

    def _attack_bruteforce(self, cracker: PasswordCracker, args: Namespace, processes: int) -> Optional[str]:
        custom_charsets = {}
        if args.custom_charset1:
            custom_charsets['1'] = args.custom_charset1
        if args.custom_charset2:
            custom_charsets['2'] = args.custom_charset2
        if args.custom_charset3:
            custom_charsets['3'] = args.custom_charset3
        if args.custom_charset4:
            custom_charsets['4'] = args.custom_charset4

        if args.wordlist2:
            return cracker.brute_force(
                mask=args.wordlist2,
                custom_charsets=custom_charsets,
                processes=processes
            )

        if args.increment:
            return cracker.brute_force(
                min_length=args.increment_min,
                max_length=args.increment_max,
                charset='a',
                custom_charsets=custom_charsets,
                processes=processes
            )

        print("[!] Warning: No mask specified, using default increment 1-4")
        return cracker.brute_force(
            min_length=1,
            max_length=4,
            charset='a',
            processes=processes
        )

    def _attack_hybrid(self, cracker: PasswordCracker, args: Namespace, processes: int, position: str) -> Optional[str]:
        if not args.wordlist or not args.wordlist2:
            print("[!] Error: Wordlist and mask required for hybrid attack")
            print(f"[!] Usage: -a {args.attack_mode} <hash> <wordlist> <mask>")
            sys.exit(1)

        if not os.path.exists(args.wordlist):
            print(f"[!] Error: Wordlist not found: {args.wordlist}")
            sys.exit(1)

        custom_charsets = {}
        if args.custom_charset1:
            custom_charsets['1'] = args.custom_charset1
        if args.custom_charset2:
            custom_charsets['2'] = args.custom_charset2
        if args.custom_charset3:
            custom_charsets['3'] = args.custom_charset3
        if args.custom_charset4:
            custom_charsets['4'] = args.custom_charset4

        return cracker.hybrid(
            wordlist_path=args.wordlist,
            mask=args.wordlist2,
            position=position,
            custom_charsets=custom_charsets,
            processes=processes
        )

    def _attack_rules(self, cracker: PasswordCracker, args: Namespace, processes: int) -> Optional[str]:
        if not args.wordlist:
            print("[!] Error: Wordlist required for rules attack")
            sys.exit(1)

        if not args.rules_file:
            print("[!] Error: At least one rules file required (-r)")
            sys.exit(1)

        if not os.path.exists(args.wordlist):
            print(f"[!] Error: Wordlist not found: {args.wordlist}")
            sys.exit(1)

        for rules_file in args.rules_file:
            if not os.path.exists(rules_file) and not any(c in rules_file for c in ":c$u^]"):
                print(f"[!] Warning: '{rules_file}' not found. Assuming it's a named preset or raw rule.")

        return cracker.rules(
            wordlist_path=args.wordlist,
            rules=args.rules_file,
            stack=args.rules_stack,
            processes=processes
        )


def main():
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
