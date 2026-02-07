# Password Cracker

A modular, multiprocessing-capable password cracking tool written in Python. Designed for security research and password
recovery with support for multiple attack modes and hash algorithms.

## 🔑 Features

- **Multi-Strategy Attacks**: Supports 6 different attack modes similar to industry-standard tools
- **Wide Hash Support**: Handles MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, BLAKE2b, BLAKE3, and more
- **Smart Optimization**: Automatically switches to single-threaded mode for small wordlists to reduce overhead
- **Session Management**: Interrupt & Resume - Press `Ctrl+C` to pause an attack safely. The tool automatically saves
  progress and allows resuming from checkpoints
- **Traceback Support**: Fully supports Windows `UTF-8-SIG` (BOM) to handle wordlists from different sources
- **Potfile Support**: Automatically caches cracked hashes to `cache/cracked.potfile` for instant future lookups
- **Hash Support**: Auto-detects and cracks MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, BLAKE2b, BLAKE3, and more.
  Handles both string and hexadecimal salts (configurable position: before/after)

## 📦 Installation

Requires **Python 3.8+**. No external dependencies are strictly required (uses standard library only).

```bash
# Clone the repository
git clone https://github.com/VKDownBG/password-cracker.git
cd password-cracker

# Install the package
pip install -e .
```

## 🚀 Running the Tool

You can run the tool as a module after installation:

```bash
# As a module
python -m hash_cracker.cli --help

# As a command (after installation)
cracker --help
```

## 🎯 Attack Modes

Use the `-a` flag to specify the attack mode:

| Mode  | Name        | Description                                             | Example                                 |
|-------|-------------|---------------------------------------------------------|-----------------------------------------|
| **0** | Dictionary  | Tries each password from a wordlist                     | `-a 0 <hash> wordlist.txt`              |
| **1** | Combinator  | Combines words from two wordlists (left + right)        | `-a 1 <hash> list1.txt list2.txt`       |
| **3** | Brute-Force | Tries all combinations of characters (Mask/Incremental) | `-a 3 <hash> ?l?l?l?d?d`                |
| **6** | Hybrid      | Wordlist + Mask (e.g., password + 123)                  | `-a 6 <hash> wordlist.txt ?d?d?d`       |
| **7** | Hybrid      | Mask + Wordlist (e.g., 123 + password)                  | `-a 7 <hash> ?d?d?d wordlist.txt`       |
| **9** | Rules-based | Applies transformation rules to wordlist                | `-a 9 <hash> wordlist.txt -r rules.txt` |

## 📖 Usage Examples

### Hash Utilities

```bash
# Identify hash algorithm
cracker --hash-info 5f4dcc3b5aa765d61d8327deb882cf99

# Generate hash from text
cracker --generate password md5

# Verify password against hash
cracker --verify password 5f4dcc3b5aa765d61d8327deb882cf99 md5

# Show all cracked passwords
cracker --show

# Show specific cracked password
cracker --show 5f4dcc3b5aa765d61d8327deb882cf99
```

### Dictionary Attack (Mode 0)

```bash
# Basic dictionary attack
cracker -a 0 -m md5 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt

# With verbose output
cracker -a 0 -m md5 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt -v

# Auto-detect hash type
cracker -a 0 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt

# With higher workload (more processes)
cracker -a 0 -m md5 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt -w 4
```

### Rules-Based Attack (Mode 9)

```bash
# Apply a single rules file
cracker -a 9 -m md5 <hash> wordlist.txt -r rules/best64.rule

# Apply multiple rules files (stacked)
cracker -a 9 -m md5 <hash> wordlist.txt -r rule1.rule -r rule2.rule --rules-stack
```

**Common Rule Transformations:**

- `:` - No change (original word)
- `c` - Capitalize first letter
- `u` - Uppercase all
- `l` - Lowercase all
- `$X` - Append character X
- `^X` - Prepend character X
- `d` - Duplicate word (e.g., passwordpassword)

### Brute-Force Attack (Mode 3)

#### Mask Attack

```bash
# Simple mask (lowercase letters + digits)
cracker -a 3 -m md5 <hash> ?l?l?l?d?d

# Mixed case letters
cracker -a 3 -m md5 <hash> ?u?l?l?l?d?d?d

# With custom charset
cracker -a 3 -m md5 <hash> -1 ?l?u ?1?1?1?1?1

# Multiple custom charsets
cracker -a 3 -m md5 <hash> -1 ?l?u -2 ?d?s ?1?1?1?2?2
```

**Built-in Charsets:**

- `?l` - Lowercase letters (a-z)
- `?u` - Uppercase letters (A-Z)
- `?d` - Digits (0-9)
- `?s` - Special characters (!@#$%...)
- `?a` - All printable ASCII
- `?b` - All bytes (0x00-0xFF)

**Custom Charsets:**

- `-1 ABC` - Define charset 1 as "ABC"
- `-2 ?l?u` - Define charset 2 as lowercase + uppercase
- Use in mask: `?1?1?1` or `?2?2?2`

#### Incremental Mode

```bash
# Try all combinations from length 1 to 4
cracker -a 3 -m md5 <hash> --increment --increment-min 1 --increment-max 4

# Longer passwords (be careful - this can take a VERY long time!)
cracker -a 3 -m md5 <hash> --increment --increment-min 6 --increment-max 8
```

### Hybrid Attacks

```bash
# Wordlist + Mask (Mode 6)
# Tries: password123, password456, admin999, etc.
cracker -a 6 -m md5 <hash> wordlist.txt ?d?d?d

# Mask + Wordlist (Mode 7)
# Tries: 123password, 456admin, 999test, etc.
cracker -a 7 -m md5 <hash> ?d?d?d wordlist.txt
```

### Combinator Attack (Mode 1)

```bash
# Combine two wordlists
cracker -a 1 -m md5 <hash> wordlist1.txt wordlist2.txt

# Example: combines "john" + "123" = "john123"
```

### Salted Hashes

```bash
# With salt appended (default)
cracker -a 0 -m md5 <hash> wordlist.txt --salt mysalt

# With salt prepended
cracker -a 0 -m md5 <hash> wordlist.txt --salt mysalt --salt-position before

# With hexadecimal salt
cracker -a 0 -m md5 <hash> wordlist.txt --hex-salt --salt 48656c6c6f
```

### Session Management

```bash
# Start attack with session name
cracker -a 0 -m md5 <hash> wordlist.txt --session mysession

# Press Ctrl+C to interrupt - progress is saved automatically

# Resume session (will prompt to continue)
cracker -a 0 -m md5 <hash> wordlist.txt --session mysession

# Restore session by name
cracker --restore mysession

# Custom checkpoint interval (default: 60 seconds)
cracker -a 0 -m md5 <hash> wordlist.txt --session mysession --checkpoint-interval 30
```

## ⚙️ Performance Options

The `-w` flag sets the exact number of worker processes.

* **Default:** 4 processes
* **Recommendation:** Set this to your physical CPU core count.

| Flag     | Description                                                    |
|:---------|:---------------------------------------------------------------|
| `-w 1`   | **Low:** Minimal CPU usage, keeps PC responsive.               |
| `-w 4`   | **Default:** Balanced for standard quad-core CPUs.             |
| `-w 8`   | **High:** Recommended for 8-core CPUs (Ryzen 7 / i7).          |
| `-w 16+` | **Max:** Extreme performance for high-end CPUs (Ryzen 9 / i9). |

# Example: Using 8 workers

cracker -a 0 -m md5 <hash> wordlist.txt -w 8

```

## 📋 Output Options

```bash
# Verbose mode (show progress)
cracker -a 0 -m md5 <hash> wordlist.txt -v

# Quiet mode (only show results)
cracker -a 0 -m md5 <hash> wordlist.txt --quiet
```

## 🗂️ Supported Hash Algorithms

The tool automatically detects hash types or you can specify with `-m`:

- **MD5** (`-m md5`)
- **SHA1** (`-m sha1`)
- **SHA256** (`-m sha256`)
- **SHA512** (`-m sha512`)
- **SHA3-256** (`-m sha3-256`)
- **SHA3-512** (`-m sha3-512`)
- **BLAKE2b** (`-m blake2b`)
- **BLAKE3** (`-m blake3`)

## 📁 Project Structure

```
password-cracker/
├── cache/                  # Runtime storage (IGNORED by Git)
│   ├── cracked.potfile     # Database of cracked hashes
│   └── session_*.json      # Saved sessions for resuming attacks
│
├── password_cracker/       # Main Source Package
│   ├── algorithms/         # Hashing logic (MD5, SHA1, etc.)
│   │   └── factory.py      # Factory pattern for hash selection
│   │   └── argon2_hasher.py # Argon2 hashing engine
│   │   └── blake3_hasher.py # BLAKE3 hashing engine
│   │   └── md5_hasher.py    # MD5 hashing engine
│   │   └── sha1_hasher.py   # SHA1 hashing engine
│   │   └── sha256_hasher.py   # SHA256 hashing engine
│   │   └── sha3_hasher.py   # SHA3 hashing engine
│   │   └── ripemd160_hasher.py   # RIPEMD-160 hashing engine
│   │
│   ├── core/               # Core Application Logic
│   │   ├── cracker.py      # Session management & orchestration
│   │   └── hasher.py       # Hash verification & generation engine
│   │
│   ├── strategies/         # Attack Implementations
│   │   ├── base_strategy.py # Abstract base class for all attacks
│   │   ├── brute_force.py   # Mode 3: Mask & Incremental attacks
│   │   ├── combinator.py    # Mode 1: Left/Right wordlist combination
│   │   ├── dictionary.py    # Mode 0: Straight wordlist attack
│   │   ├── hybrid.py        # Mode 6/7: Wordlist + Mask combinations
│   │   └── rules.py         # Mode 9: Rule-based wordlist mangling
│   │
│   ├── utils/              # Helper Modules
│   │   ├── mangling/       # Rule processing & wordlist readers
│   │   └── mask_parser.py  # Custom charset & mask parsing logic
│   │
│   ├── __init__.py         # Package initialization
│   └── cli.py              # Entry point (Command Line Interface)
│
├── test_data/              # Data for testing (Safe to commit)
│   ├── rules/              # Rule files (e.g., simple.rule)
│   └── wordlists/          # Small wordlists (e.g., small.txt)
│
├── tests/                  # Unit Tests
│   ├── __init__.py
│   ├── test_cli.py
│   ├── test_cracker.py
│   └── test_hasher.py
│
├── .gitignore              # Git configuration
├── pyproject.toml          # Project metadata
├── README.md               # Documentation
├── requirements.txt        # Dependencies
└── sanitize.py             # Utility script
```

## 🧪 Testing

See `TEST_SUITE.md` for comprehensive testing instructions.

Quick smoke test:

```bash
# Create test wordlist
mkdir -p test_data/wordlists
echo -e "password\nadmin\ntest" > test_data/wordlists/test.txt

# Test hash identification
cracker --hash-info 5f4dcc3b5aa765d61d8327deb882cf99

# Test dictionary attack
cracker -a 0 -m md5 5f4dcc3b5aa765d61d8327deb882cf99 test_data/wordlists/test.txt

# Test brute force
cracker -a 3 -m md5 900150983cd24fb0d6963f7d28e17f72 ?l?l?l

# Show cracked passwords
cracker --show
```

## 🔒 Security & Legal Notice

**This tool is for educational and authorized security testing purposes only.**

- ⚠️ Only use on systems you own or have explicit permission to test
- ⚠️ Unauthorized password cracking is illegal in most jurisdictions
- ⚠️ The developers assume no liability for misuse of this software

By using this tool, you agree to use it responsibly and legally.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by industry-standard tools like Hashcat and John the Ripper
- Built with Python's multiprocessing for efficient parallel processing
- Designed for educational purposes and security research

## 📞 Contact

https://www.linkedin.com/in/valeri-kirilov-24a21438b 

---

**Happy (legal) cracking! 🔓**