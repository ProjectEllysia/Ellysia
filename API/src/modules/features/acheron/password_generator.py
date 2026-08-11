"""Generador de contraseñas aleatorias seguras.

Utilidad sin estado: no depende de vaults, usuarios ni base de datos.
Usa `secrets` (CSPRNG) para toda la aleatoriedad, igual que el resto
de generación de secretos en la API (ver users/managers.py).
"""

import secrets
import string

_AMBIGUOUS = set("0O1lI")
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(
    length: int,
    use_uppercase: bool,
    use_lowercase: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
) -> str:
    pools = []
    if use_uppercase:
        pools.append(string.ascii_uppercase)
    if use_lowercase:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(_SYMBOLS)

    if exclude_ambiguous:
        pools = ["".join(character for character in pool if character not in _AMBIGUOUS) for pool in pools]

    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
