"""Bounded, offline address and direct payment-request recognition.

Original implementation of the format definitions in BIP-173/350, ERC-55/681,
BIP-321's direct-address subset, XRPL classic addresses, and Monero addresses.
No CryptoScan source or reference-implementation code is copied here. Constants
are protocol constants. See THIRD_PARTY_NOTICES.md for specifications and credits.
Matches establish text/format evidence, never ownership, balances, or a payment.
"""

from collections.abc import Iterator
import hashlib
import re
from urllib.parse import unquote


MAX_ARTIFACT_BYTES = 4096
MAX_BUFFER_BYTES = 4 * 1024 * 1024
_BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_BECH_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BASE58_CHARS = "1-9A-HJ-NP-Za-km-z"
# Prefix bytes identify an address type/network; they do not prove chain use.
_XMR_PREFIXES = {
    18: ("standard", "mainnet", 69), 19: ("integrated", "mainnet", 77),
    42: ("subaddress", "mainnet", 69),
    53: ("standard", "testnet", 69), 54: ("integrated", "testnet", 77),
    63: ("subaddress", "testnet", 69),
    24: ("standard", "stagenet", 69), 25: ("integrated", "stagenet", 77),
    36: ("subaddress", "stagenet", 69),
}
_ADDRESS = (
    r"(?i:bc1|tb1)[A-Za-z0-9]{6,87}"
    r"|0x[0-9a-fA-F]{40}"
    rf"|[13mn2][{_BASE58_CHARS}]{{25,34}}"
    rf"|r[{_BASE58_CHARS}]{{24,34}}"
    rf"|[45789AB][{_BASE58_CHARS}]{{105}}|[45789AB][{_BASE58_CHARS}]{{94}}"
)
_ADDRESS_RE = re.compile(rf"(?<![A-Za-z0-9_])(?:{_ADDRESS})(?![A-Za-z0-9_])")
_URI_CHAR = r"[^\x00-\x20\x7f-\xff<>\"'\\]"
_TOKEN_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<uri>(?i:bitcoin|ethereum):{_URI_CHAR}{{1,2039}})(?!{_URI_CHAR})"
    rf"|(?<![A-Za-z0-9_])(?P<address>{_ADDRESS})(?![A-Za-z0-9_])"
)
_WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")
_FIELD = re.compile(r'''["'](address|recipient|to)["']\s*:\s*["']$''', re.I)


def _base58(value: str, alphabet: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + alphabet.index(char)
    zeros = len(value) - len(value.lstrip(alphabet[0]))
    return b"\x00" * zeros + number.to_bytes((number.bit_length() + 7) // 8, "big")


def _double_sha(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58_result(value: str, currency: str) -> dict[str, str]:
    raw = _base58(value, _BTC_ALPHABET if currency == "BTC" else _XRP_ALPHABET)
    result = {
        "currency": currency,
        "canonical": value,
        "format": "Base58Check" if currency == "BTC" else "XRP-classic",
        "network": "unspecified",
    }
    versions = {0: "P2PKH", 5: "P2SH", 111: "P2PKH", 196: "P2SH"}
    if len(raw) != 25 or (raw[0] not in versions if currency == "BTC" else raw[0] != 0):
        return result | {"validation": "malformed", "reason": "Unsupported version or decoded payload length"}
    if currency == "BTC":
        result["format"] = "Base58Check-" + versions[raw[0]]
        result["network"] = "bitcoin-mainnet-compatible" if raw[0] in (0, 5) else "bitcoin-testnet-compatible"
    valid = _double_sha(raw[:-4])[:4] == raw[-4:]
    return result | {
        "validation": "checksum_valid" if valid else "checksum_invalid",
        "reason": "Version, 20-byte payload and checksum validated" if valid else "Base58Check checksum mismatch",
    }


def _bech_result(value: str) -> dict[str, str]:
    lower = value.lower()
    result = {"currency": "BTC", "canonical": lower, "format": "SegWit", "network": "unspecified"}
    if value != lower and value != value.upper():
        return result | {"validation": "malformed", "reason": "Mixed-case Bech32 text"}
    hrp, encoded = lower.split("1", 1)
    result["network"] = "bitcoin-mainnet-compatible" if hrp == "bc" else "bitcoin-testnet-compatible"
    if len(value) > 90 or any(char not in _BECH_ALPHABET for char in encoded):
        return result | {"validation": "malformed", "reason": "Invalid Bech32 alphabet or length"}
    digits = [_BECH_ALPHABET.index(char) for char in encoded]
    if len(digits) < 7 or digits[0] > 16:
        return result | {"validation": "malformed", "reason": "Missing or unsupported witness version"}
    version = digits[0]
    result["format"] = "Bech32-v0" if version == 0 else f"Bech32m-v{version}"
    # Polynomial remainder over the expanded HRP and encoded 5-bit symbols.
    remainder = 1
    symbols = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp] + digits
    for digit in symbols:
        high = remainder >> 25
        remainder = ((remainder & 0x1FFFFFF) << 5) ^ digit
        for bit, generator in enumerate(_BECH_GENERATORS):
            if high & (1 << bit):
                remainder ^= generator
    if remainder != (1 if version == 0 else 0x2BC830A3):
        return result | {"validation": "checksum_invalid", "reason": "Checksum mismatch or wrong checksum variant for witness version"}
    bits = "".join(f"{digit:05b}" for digit in digits[1:-6])
    tail_length = len(bits) % 8
    if tail_length >= 5 or (tail_length and "1" in bits[-tail_length:]):
        return result | {"validation": "malformed", "reason": "Invalid witness-program padding"}
    program_length = len(bits) // 8
    if not 2 <= program_length <= 40 or (version == 0 and program_length not in (20, 32)):
        return result | {"validation": "malformed", "reason": "Invalid witness-program length"}
    return result | {"validation": "checksum_valid", "reason": "Checksum, witness version, program length and padding validated"}


def _eth_result(value: str) -> dict[str, str]:
    body = value[2:]
    result = {"currency": "ETH", "canonical": value.lower(), "format": "EVM-hex", "network": "unspecified"}
    if body == body.lower() or body == body.upper():
        return result | {"validation": "format_only", "reason": "20-byte hex form; uniform case is not treated as checksum evidence; chain unknown"}
    keccak = _keccak_module()
    digest = keccak.new(digest_bits=256, data=body.lower().encode("ascii")).hexdigest()
    valid = all(not char.isalpha() or char.isupper() == (int(digest[index], 16) >= 8) for index, char in enumerate(body))
    return result | {
        "format": "ERC-55",
        "validation": "checksum_valid" if valid else "checksum_invalid",
        "reason": "ERC-55 checksum validated; chain unknown" if valid else "ERC-55 checksum mismatch; chain unknown",
    }


def _keccak_module():
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:
        raise ImportError("CryptoMem Ethereum/Monero checksum validation requires pycryptodome==3.23.0") from exc
    return keccak


def check_dependencies(currencies: set[str]) -> None:
    """Fail clearly before scanning when selected validation is unavailable."""
    if currencies & {"ETH", "XMR"}:
        _keccak_module()


def _xmr_result(value: str) -> dict[str, str]:
    result = {"currency": "XMR", "canonical": value, "format": "Monero-Base58", "network": "unspecified"}
    if len(value) not in (95, 106) or any(char not in _BTC_ALPHABET for char in value):
        return result | {"validation": "malformed", "reason": "Invalid Monero alphabet or encoded length"}
    # Monero encodes each 8-byte block separately as 11 padded characters.
    # Both supported payload sizes end in a 5-byte block (7 characters).
    raw = bytearray()
    for start in range(0, len(value), 11):
        block = value[start:start + 11]
        number = 0
        for char in block:
            number = number * 58 + _BTC_ALPHABET.index(char)
        size = 8 if len(block) == 11 else 5
        if number >= 1 << (8 * size):
            return result | {"validation": "malformed", "reason": "Monero Base58 block overflow"}
        raw.extend(number.to_bytes(size, "big"))
    prefix = _XMR_PREFIXES.get(raw[0])
    if prefix is None or len(raw) != prefix[2]:
        return result | {"validation": "malformed", "reason": "Unsupported Monero prefix or address-type payload length"}
    kind, network, _ = prefix
    result.update(format="Monero-" + kind, network="monero-" + network + "-compatible")
    digest = _keccak_module().new(digest_bits=256, data=bytes(raw[:-4])).digest()
    valid = digest[:4] == raw[-4:]
    return result | {
        "validation": "checksum_valid" if valid else "checksum_invalid",
        "reason": ("Block encoding, address-type/network prefix, length and Keccak checksum validated; "
                   "public-key curve validity and wallet ownership are not checked") if valid
                  else "Monero Keccak checksum mismatch",
    }


def _address_currency(value: str) -> str:
    if value.startswith("0x"):
        return "ETH"
    if len(value) in (95, 106):
        return "XMR"
    return "XRP" if value.startswith("r") else "BTC"


def _address_result(value: str) -> dict[str, str]:
    if _address_currency(value) == "XMR":
        return _xmr_result(value)
    if value.startswith("0x"):
        return _eth_result(value)
    if value.lower().startswith(("bc1", "tb1")):
        return _bech_result(value)
    return _base58_result(value, "XRP" if value.startswith("r") else "BTC")


def _query(text: str, casefold: bool) -> dict[str, str]:
    if not text:
        return {}
    # RFC 3986 query = *(pchar / "/" / "?"). Validate the encoded form so
    # forbidden raw characters remain malformed evidence instead of being
    # silently accepted; percent-encoded label/message content stays valid.
    if not re.fullmatch(r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*", text):
        raise ValueError("Invalid raw query character or percent escape")
    parts = text.split("&")
    if len(parts) > 16:
        raise ValueError("More than 16 query fields")
    result = {}
    for part in parts:
        if "=" not in part:
            raise ValueError("Malformed query field")
        key, value = (unquote(item, encoding="utf-8", errors="strict") for item in part.split("=", 1))
        key = key.lower() if casefold else key
        if not key or key in result:
            raise ValueError("Empty or duplicate query field")
        if any(ord(char) < 32 or ord(char) == 127 for char in key + value):
            raise ValueError("Control character in query field")
        result[key] = value
    return result


def _wei_amount(value: str) -> bool:
    # Check integer atomic units without expanding an attacker-controlled exponent.
    match = re.fullmatch(r"\+?([0-9]+)(?:\.([0-9]+))?(?:[eE]([0-9]{1,3}))?", value)
    if not match:
        return False
    whole, fraction, exponent = match.groups()
    fraction = fraction or ""
    exponent_value = int(exponent or "0")
    if exponent_value < len(fraction) or exponent_value > 77:
        return False
    digits = (whole + fraction).lstrip("0") or "0"
    zero_count = exponent_value - len(fraction)
    if len(digits) + zero_count > 78:
        return False
    return int(digits + "0" * zero_count) < 2**256


def _payment_result(value: str) -> dict[str, str]:
    scheme, body = value.split(":", 1)
    btc = scheme.lower() == "bitcoin"
    currency = "BTC" if btc else "ETH"
    result = {
        "currency": currency, "canonical": "", "format": "BIP-321-direct" if btc else "ERC-681-direct",
        "network": "unspecified", "amount": "", "validation": "unsupported",
        "reason": "Only a direct address and supported optional fields are interpreted",
    }
    if "#" in body or body.startswith("//"):
        return result | {"reason": "URI fragment or authority syntax is unsupported"}
    target, separator, query = body.partition("?")
    if not btc and target.startswith("pay-"):
        target = target[4:]
    if "/" in target:
        return result | {"reason": "Contract/function requests are unsupported"}
    if not btc and "@" in target:
        target, chain = target.split("@", 1)
        if not re.fullmatch(r"[0-9]{1,78}", chain):
            return result | {"validation": "malformed", "reason": "Invalid declared chain ID"}
        result["network"] = "declared-chain-id:" + chain
    if not _ADDRESS_RE.fullmatch(target):
        return result | {"reason": "Missing or unsupported direct address; names are never resolved"}
    if _address_currency(target) != currency:
        return result | {"validation": "malformed", "reason": "Address does not match URI scheme"}
    address = _address_result(target)
    result["canonical"] = address["canonical"]
    if btc:
        result["network"] = address["network"]
    try:
        params = _query(query, btc)
    except (ValueError, UnicodeError) as exc:
        return result | {"validation": "malformed", "reason": str(exc)}
    allowed = {"amount", "label", "message"} if btc else {"value", "gas", "gasLimit", "gasPrice"}
    if params.keys() - allowed:
        return result | {"reason": "Unsupported query fields, required extensions or alternate payment instructions"}
    amount = params.get("amount" if btc else "value", "")
    if btc and "amount" in params and not re.fullmatch(r"[0-9]{1,16}(?:\.[0-9]{1,8})?", amount):
        return result | {"validation": "malformed", "reason": "Invalid BTC amount; expected a nonnegative decimal with at most eight fractional digits"}
    if not btc and any(not _wei_amount(item) for item in params.values()):
        return result | {"validation": "malformed", "reason": "Invalid ERC-681 numeric value; expected nonnegative integer atomic units within uint256"}
    if separator and not query:
        return result | {"validation": "malformed", "reason": "Empty query delimiter"}
    return result | {
        "amount": amount,
        "validation": address["validation"],
        "reason": "Direct payment-request subset; amount is requested, not paid. " + address["reason"],
    }


def _record(result: dict[str, str], value: str, offset: int, width: int, kind: str, context: str) -> dict:
    return result | {
        "value": value, "offset": offset, "length": len(value) * width, "kind": kind,
        "encoding": "ascii" if width == 1 else "utf-16le", "context": context,
        "amount": result.get("amount", ""),
    }


def _text_artifacts(text: str, base: int, width: int, currencies: set[str]) -> Iterator[dict]:
    for match in _TOKEN_RE.finditer(text):
        value = match.group()
        offset = base + match.start() * width
        if match.group("uri"):
            currency = "BTC" if value[:8].lower() == "bitcoin:" else "ETH"
            if currency in currencies:
                result = _payment_result(value)
                yield _record(result, value, offset, width, "payment_request", "payment_request")
            for address_match in _ADDRESS_RE.finditer(value):
                address = address_match.group()
                currency = _address_currency(address)
                if currency not in currencies:
                    continue
                result = _address_result(address)
                yield _record(result, address, offset + address_match.start() * width, width, "address", "payment_request_text")
        else:
            # A filter must not trigger an optional dependency for another currency.
            currency = _address_currency(value)
            if currency not in currencies:
                continue
            result = _address_result(value)
            field = _FIELD.search(text[max(0, match.start() - 64):match.start()])
            context = "field:" + field.group(1).lower() if field else "standalone_address"
            yield _record(result, value, offset, width, "address", context)


def find_artifacts(data: bytes, currencies: set[str]) -> Iterator[dict]:
    """Yield bounded candidates with exact byte offsets within a contiguous buffer.

    The caller owns chunk overlap, unreadable-page boundaries, deduplication,
    output limits, and process/coverage attribution. No memory/network I/O occurs.
    Uniform-case EVM text is deliberately format_only, even when it happens to
    equal an ERC-55 test vector. XRP classic and EVM text imply no specific chain.
    """
    if not isinstance(data, bytes) or len(data) > MAX_BUFFER_BYTES:
        raise ValueError("CryptoMem detector requires bytes in buffers no larger than 4 MiB")
    if not isinstance(currencies, set) or currencies - {"BTC", "ETH", "XRP", "XMR"}:
        raise ValueError("currencies must be a set containing only BTC, ETH, XRP, XMR")
    if not currencies:
        return
    yield from _text_artifacts(data.decode("latin-1"), 0, 1, currencies)
    # Explicit printable ASCII code units preserve offsets even beside malformed
    # UTF-16 or surrogate pairs. Runs can start on either byte alignment.
    for run in _WIDE_RUN.finditer(data):
        yield from _text_artifacts(run.group().decode("utf-16-le"), run.start(), 2, currencies)
