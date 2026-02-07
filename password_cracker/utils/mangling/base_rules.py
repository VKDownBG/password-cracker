def capitalize_first(word: str) -> str:
    """ 'c' : capitalize the first letter """
    if not word:
        return word
    return word[0].upper() + word[1:]


def lowercase_first_uppercase_rest(word: str) -> str:
    """ 'C' : lower first, upper the rest (e.g. pASSWORD) """
    if not word:
        return word
    return word[0].lower() + word[1:].upper()


def toggle_case(word: str) -> str:
    """ 'T' : swap case (e.g. Password -> pASSWORD) """
    return word.swapcase()


def uppercase_all(word: str) -> str:
    """ 'u' : uppercase the whole word """
    return word.upper()


def lowercase_all(word: str) -> str:
    """ 'l' : lowercase the whole word """
    return word.lower()


def prepend_char(word: str, char: str) -> str:
    """ '^X' : add char to start """
    return char + word


def append_char(word: str, char: str) -> str:
    """ '$X' : add char to end """
    return word + char


def truncate_first(word: str) -> str:
    """ '[' : remove first char"""
    return word[1:]


def truncate_last(word: str) -> str:
    """ ']' : remove last char"""
    return word[:-1]


def purge_char(word: str, char: str) -> str:
    """ '@X' : remove all chars matching X """
    return word.replace(char, '')


def reverse_word(word: str) -> str:
    """ 'r' : reverse the word """
    return word[::-1]


def rotate_left(word: str) -> str:
    """ '{' : move first char to end """
    if len(word) < 2:
        return word
    return word[1:] + word[0]


def rotate_right(word: str) -> str:
    """ '}' : move last char to start """
    if len(word) < 2:
        return word
    return word[-1] + word[:-1]


def duplicate_word(word: str) -> str:
    """ 'd' : append word to itself """
    return word + word


def reflect(word: str) -> str:
    """ 'f' : append reverse of word (palindrome) """
    return word + word[::-1]


def substitute(word: str, old_char: str, new_char: str) -> str:
    """ 'sXY' : replace X with Y """
    return word.replace(old_char, new_char)


def insert_at(word: str, pos: int, char_to_insert: str) -> str:
    """ 'iXY' : insert char X at position N"""
    if pos < 0 or pos > len(word):
        return word

    return word[:pos] + char_to_insert + word[pos:]


def overwrite_at(word: str, pos: int, new_char: str) -> str:
    """ 'oXY' : overwrite char X at position N """
    if pos < 0 or pos >= len(word):
        return word

    return word[:pos] + new_char + word[pos + 1:]


def swap_chars(word: str, pos1: int, pos2: int) -> str:
    """ '*NM' : swap chars at position N and M """
    if pos1 < 0 or pos1 >= len(word) or pos2 < 0 or pos2 >= len(word):
        return word

    chars = list(word)
    chars[pos1], chars[pos2] = chars[pos2], chars[pos1]
    return "".join(chars)


def increment_char(word: str, pos: int) -> str:
    """ '+N' : increment char at position N """
    if pos < 0 or pos >= len(word):
        return word

    char_code = ord(word[pos])
    new_char = chr(char_code + 1)

    return word[:pos] + new_char + word[pos + 1:]


def decrement_char(word: str, pos: int) -> str:
    """ '-N' : decrement char at position N """
    if pos < 0 or pos >= len(word):
        return word

    char_code = ord(word[pos])

    if char_code == 0:
        return word

    new_char = chr(char_code - 1)

    return word[:pos] + new_char + word[pos + 1:]


def delete_at(word: str, pos: int) -> str:
    """ 'DX' : delete char at position N """
    if pos < 0 or pos >= len(word):
        return word
    return word[:pos] + word[pos + 1:]


def truncate_to_length(word: str, length: int) -> str:
    """ ''N' : truncate word to length N """
    if length < 0:
        return word
    return word[:length]


def toggle_at(word: str, pos: int) -> str:
    """ 'tN' : toggle case at position N """
    if pos < 0 or pos >= len(word):
        return word

    char = word[pos]
    new_char = char.lower() if char.isupper() else char.upper()

    return word[:pos] + new_char + word[pos + 1:]


RULE_MAP = {
    # --- No Operations ---
    ':': None,

    # --- Case ---
    'c': capitalize_first,
    'u': uppercase_all,
    'l': lowercase_all,
    'T': toggle_case,
    'C': lowercase_first_uppercase_rest,

    # --- Additions ---
    '^': prepend_char,
    '$': append_char,

    # --- Deletions/Purge ---
    '[': truncate_first,
    ']': truncate_last,
    '@': purge_char,

    # --- Structure ---
    'r': reverse_word,
    '{': rotate_left,
    '}': rotate_right,
    'd': duplicate_word,
    'f': reflect,

    # --- Substitution ---
    's': substitute,

    # --- Positional Editing ---
    'i': insert_at,
    'o': overwrite_at,
    '*': swap_chars,
    '+': increment_char,
    '-': decrement_char,
    'D': delete_at,
    "'": truncate_to_length,
    't': toggle_at,
}
