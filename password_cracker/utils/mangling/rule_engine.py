from .base_rules import RULE_MAP
from functools import lru_cache


def parse_position(char: str) -> int:
    if char.isdigit():
        return int(char)
    elif char.isupper():
        return ord(char) - 55
    return -1


@lru_cache(maxsize=1024)
def parse_rule(rule_string: str) -> list[tuple[str, list]]:
    operations = []
    i = 0
    n = len(rule_string)

    if not rule_string:
        return [(':', [])]

    while i < len(rule_string):
        char = rule_string[i]

        if char in ':culTC[]r{}df':
            operations.append((char, []))
            i += 1

        elif char in '^$@':
            if i + 1 >= n:
                raise ValueError(f"Rule '{char}' at position {i} requires 1 parameter")
            operations.append((char, [rule_string[i + 1]]))
            i += 2

        elif char in '+-D\'t':
            if i + 1 >= n:
                raise ValueError(f"Rule '{char}' at position {i} requires 1 parameter")
            operations.append((char, [parse_position(rule_string[i + 1])]))
            i += 2

        elif char == 's':
            if i + 2 >= n:
                raise ValueError(f"Rule 's' at position {i} requires 2 parameters")
            operations.append(('s', [rule_string[i + 1], rule_string[i + 2]]))
            i += 3

        elif char in 'io':
            if i + 2 >= n:
                raise ValueError(f"Rule '{char}' at position {i} requires 2 parameters")
            operations.append((char, [parse_position(rule_string[i + 1]), rule_string[i + 2]]))
            i += 3

        elif char == '*':
            if i + 2 >= n:
                raise ValueError(f"Rule '*' at position {i} requires 2 parameters")
            operations.append(('*', [parse_position(rule_string[i + 1]), parse_position(rule_string[i + 2])]))
            i += 3

        else:
            raise ValueError(f"Invalid character '{char}' at position {i}")

    return operations


def apply_rule(word: str, rule_string: str) -> str:
    operations = parse_rule(rule_string)
    result = word

    for rule_char, params in operations:
        func = RULE_MAP[rule_char]

        if func is None:
            continue

        result = func(result, *params)

    return result


def clean_and_extract_rule(line: str) -> str:
    cleaned_rule = []
    i = 0
    n = len(line)

    ZERO_PARAM = set(":culTC[]r{}df")
    ONE_PARAM = set("^$@+-D\'t")
    TWO_PARAM = set("sio*")

    while i < n:
        char = line[i]

        if char == '#':
            break

        if char == '#' or char.isspace():
            if not cleaned_rule:
                i += 1
                continue
            else:
                break

        cleaned_rule.append(char)

        params_needed = 0
        if char in ONE_PARAM:
            params_needed = 1
        elif char in TWO_PARAM:
            params_needed = 2
        elif char not in ZERO_PARAM:
            pass

        i += 1

        while params_needed > 0 and i < n:
            cleaned_rule.append(line[i])
            i += 1
            params_needed -= 1

    return "".join(cleaned_rule)


def load_rule_file(filepath: str) -> list[str]:
    try:
        with open(filepath) as fd:
            rules = []
            for line in fd:
                rule = clean_and_extract_rule(line)

                if rule:
                    rules.append(rule)

            return rules
    except FileNotFoundError:
        raise FileNotFoundError(f"Rule file not found: {filepath}")
