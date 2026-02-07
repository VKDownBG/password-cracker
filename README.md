Python Password CrackerA modular, multiprocessing-capable password cracking tool written in Python. Designed for flexibility and ease of use, it supports multiple attack strategies (Dictionary, Brute-Force, Rules, Hybrid, Combinator) and includes advanced features like session resumption, smart optimization for small workloads, and potfile caching.⚡ FeaturesMulti-Strategy Attacks: Supports 6 different attack modes similar to industry standards (Hashcat/JtR).Multiprocessing: Utilizes full CPU power with configurable worker processes (-w).Smart Optimization: Automatically switches to single-threaded mode for small wordlists/tasks to avoid multiprocessing overhead.Session Management:Interrupt & Resume: Press Ctrl+C to pause an attack safely. The tool performs an emergency save to preserve progress.Restore: Resume attacks exactly where they left off using --restore.Potfile Support: Automatically caches cracked hashes to cache/cracked.potfile to prevent re-cracking known passwords.Encoding Safe: Fully supports Windows UTF-8-SIG (BOM) to handle wordlists and rules without encoding errors.Hash Support: Auto-detects and cracks MD5, SHA1, SHA256, and SHA512.Salt Support: Handles static salts (prefix/suffix) in both string and hexadecimal formats.🚀 InstallationRequires Python 3.8+. No external dependencies are strictly required (uses standard libraries).Bash# Clone the repository
git clone https://github.com/VKDownBG/password-cracker.git

# Navigate to the directory
cd password-cracker
Running the ToolYou can run the tool as a module:Bashpython -m hash_cracker.cli --help
Note: The examples below use the alias cracker for brevity.🛠 Attack ModesUse the -a flag to specify the attack mode.ModeNameDescriptionExample0DictionaryTries words from a wordlist.-a 0 <hash> wordlist.txt1CombinatorCombines words from two wordlists (Left + Right).-a 1 <hash> list1.txt list2.txt3Brute-ForceTries all combinations of characters (Mask/Incremental).-a 3 <hash> ?l?l?l?d6Hybrid (W+M)Wordlist + Mask (e.g., password + 123).-a 6 <hash> list.txt ?d?d?d7Hybrid (M+W)Mask + Wordlist (e.g., 123 + password).-a 7 <hash> ?d?d?d list.txt9RulesApplies transformation rules to a wordlist.-a 9 <hash> list.txt -r rules/best64.rule📖 Usage Examples1. Dictionary AttackStandard attack using a wordlist.Bashcracker -a 0 -m md5 5f4dcc3b5aa765d61d8327deb882cf99 wordlists/rockyou.txt
2. Brute-Force / Mask AttackBrute-force is highly configurable. You can use standard masks or custom charsets.Standard Masks:?l = Lowercase (a-z)?u = Uppercase (A-Z)?d = Digits (0-9)?s = Special (!@#...)?a = All printable ASCIIBash# Crack a 4-digit PIN
cracker -a 3 -m md5 <hash> ?d?d?d?d

# Incremental mode (Try length 1 to 5)
cracker -a 3 -m md5 <hash> --increment --increment-max 5
Custom Charsets:Use -1, -2, -3, -4 to define custom sets.Bash# Custom charset ?1 = abc, ?2 = 123
# Mask ?1?1?2?2 tries combinations like "aa11", "ab12", etc.
cracker -a 3 -m md5 <hash> -1 abc -2 123 ?1?1?2?2
3. Rules AttackApply transformation rules (like "append 1", "uppercase", "reverse") to a wordlist.Bash# Single rule file
cracker -a 9 -m md5 <hash> wordlist.txt -r rules/simple.rule

# Stacked Rules (Combinatorial)
# Applies every rule in File A combined with every rule in File B
cracker -a 9 -m md5 <hash> wordlist.txt -r file1.rule -r file2.rule --rules-stack
4. Hybrid AttackCombine the efficiency of wordlists with the flexibility of masks.Bash# Mode 6: Wordlist + Mask (e.g., "password" + "123")
cracker -a 6 -m md5 <hash> wordlist.txt ?d?d?d

# Mode 7: Mask + Wordlist (e.g., "123" + "password")
cracker -a 7 -m md5 <hash> ?d?d?d wordlist.txt
💾 Session Management (Stop & Resume)This tool is designed for long-running tasks. You can interrupt it at any time.Stop: Press Ctrl+C. The tool will catch the signal, perform an Emergency Save, and exit cleanly.Resume: Run the same command (or use --restore session_name). The tool will detect the saved session and ask to resume.Bash# To explicitly name a session
cracker -a 3 -m md5 <hash> ?a?a?a?a --session my_attack

# To restore later
cracker --restore my_attack
⚙️ Advanced OptionsSalts:--salt "mysalt": Add a static salt.--hex-salt: Interpret salt as hex bytes (e.g., --salt 41 becomes A).--salt-position before: Prepend salt (salt+pass). Default is after.Performance:-w <N>: Set number of worker processes (Default: 4).--quiet: Suppress output (useful for scripts).Utilities:--hash-info <hash>: Identify hash type and length.--generate <text> <algo>: Generate a hash for testing.--show: Show all cracked passwords in the potfile.⚠️ DisclaimerThis tool is for educational purposes and authorized security testing only. Do not use this tool on systems or data you do not own or have explicit permission to test. The authors accept no liability for unauthorized use.