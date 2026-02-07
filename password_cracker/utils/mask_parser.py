from typing import Dict, List, Tuple

BUILTIN_CHARSETS = {
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'd': '0123456789',
    's': '!@#$%^&*()-_=+[]{}|;:,.<>?/\'',
    'a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/\''
}


def parse_mask(mask: str, custom_charsets: Dict[str, str]) -> List[Tuple[str, List[str]]]:
    result = []
    i = 0

    while i < len(mask):
        if mask[i] == '?':
            if i + 1 >= len(mask):
                raise ValueError(f"[!] Invalid mark: '?' at the end of mask")

            next_char = mask[i + 1]

            if next_char == '?':
                result.append(('fixed', ['?']))
                i += 2
                continue

            if next_char in BUILTIN_CHARSETS:
                charset = list(BUILTIN_CHARSETS[next_char])
                result.append(('variable', charset))
                i += 2
                continue

            if next_char in custom_charsets:
                charset = list(custom_charsets[next_char])
                result.append(('variable', charset))
                i += 2
                continue

            raise ValueError(f"[!] Unknown placeholder: ?{next_char}")
        else:
            result.append(('fixed', [mask[i]]))
            i += 1

    return result
