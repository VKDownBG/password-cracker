from typing import Generator

from .rule_engine import apply_rule


def read_wordlist(filepath: str, start_line: int = 0) -> Generator[str, None, None]:
    try:
        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for _ in range(start_line):
                next(f, None)

            for line in f:
                word = line.strip()
                if word:
                    yield word
    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist file not found: {filepath}")


def count_lines(filepath: str) -> int:
    count = 0
    with open(filepath, 'rb') as f:
        for _ in f:
            count += 1
    return count
