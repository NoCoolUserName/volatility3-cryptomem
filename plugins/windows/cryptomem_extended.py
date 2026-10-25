"""Opt-in, bounded text-format validators. No I/O, wallet or network operations.

Original BIP-39/BIP-32 and Bitcoin WIF implementation; see repository notices.
Only recognizable serialized keys are tested, never arbitrary binary entropy.
"""
import hashlib
import re
import unicodedata
from urllib.parse import unquote

from volatility3.plugins.windows import cryptomem_bip39 as bip39
from volatility3.plugins.windows import cryptomem_formats as formats

MASK = "[REDACTED SECRET]"
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
LENGTHS = (12, 15, 18, 21, 24)
WORDS = {word: i for i, word in enumerate(bip39.WORDS.splitlines())}
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_KEY = re.compile(r"(?<![A-Za-z0-9_])(?:[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}|[xt]prv[1-9A-HJ-NP-Za-km-z]{107})(?![A-Za-z0-9_])")
_TX = re.compile(r"(?<![A-Za-z0-9_])(?:0x)?[0-9A-Fa-f]{64}(?![A-Za-z0-9_])")
_WORD = re.compile(r"[A-Za-z0-9_]+")
# Supported English transcription: ASCII, compatibility-width Latin characters,
# Unicode spacing and Latin ligatures. Other languages/encodings are unsupported.
_TEXT = re.compile(r"[\x09-\x0d\x20-\x7e\u00a0\u2000-\u200a\u202f\u205f\u3000\ufb00-\ufb06\uff01-\uff5e]+")
_LABEL = re.compile(r'''(?i)(?<![A-Za-z0-9_])(bitcoin_txid|ethereum_transaction_hash|transaction_hash|transaction[ _-]?id|txid|txhash)["']?\s*[:=]\s*["']?$''')
_EXAMPLE = re.compile(r"(?i)\b(example|test[ _-]?vector|mnemonic|seed|recovery phrase)\b")


def check_wordlist():
    if len(WORDS) != 2048 or hashlib.sha256((bip39.WORDS + "\n").encode()).hexdigest() != WORDLIST_SHA256:
        raise ValueError("Pinned BIP-39 English word list integrity failure")


def mnemonic_valid(value):
    """NFKD, exact English words/case, allowed length and SHA-256 entropy checksum.

    Whitespace transcription is collapsed; this does not derive a wallet seed.
    No lowercasing, fuzzy words, passphrase or non-BIP-39 scheme support.
    """
    words = unicodedata.normalize("NFKD", value).split()
    if len(words) not in LENGTHS or any(word not in WORDS for word in words):
        return False
    number = 0
    for word in words:
        number = (number << 11) | WORDS[word]
    checksum_bits = len(words) // 3
    entropy_bits = len(words) * 11 - checksum_bits
    entropy = (number >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    return number & ((1 << checksum_bits) - 1) == hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)


def key_result(value):
    """Validate recognizable WIF or xprv/tprv, including scalar range and roots."""
    extended = value.startswith(("xprv", "tprv"))
    result = dict(format="BIP32-private" if extended else "Bitcoin-WIF", currency="BTC",
                  network="unknown", validation="malformed", reason="Unsupported structure or version")
    try:
        raw = formats._base58(value, formats._BTC_ALPHABET)
    except ValueError:
        return result
    if len(raw) < 5 or formats._double_sha(raw[:-4])[:4] != raw[-4:]:
        return result | dict(validation="checksum_invalid", reason="Base58Check checksum mismatch")
    payload = raw[:-4]
    if extended:
        versions = {bytes.fromhex("0488ade4"): "bitcoin-mainnet-compatible",
                    bytes.fromhex("04358394"): "bitcoin-test-family-compatible"}
        if len(payload) != 78 or payload[:4] not in versions or payload[45] != 0:
            return result
        if payload[4] == 0 and payload[5:13] != b"\0" * 8:
            return result | dict(reason="Root depth requires zero parent fingerprint and child index")
        scalar = payload[46:78]
        network = versions[payload[:4]]
    else:
        if len(payload) not in (33, 34) or payload[0] not in (0x80, 0xEF):
            return result
        if len(payload) == 34 and payload[-1] != 1:
            return result | dict(reason="Invalid WIF compression marker")
        scalar = payload[1:33]
        network = "bitcoin-mainnet-compatible" if payload[0] == 0x80 else "bitcoin-test-family-compatible"
    if not 1 <= int.from_bytes(scalar, "big") < ORDER:
        return result | dict(reason="Private scalar outside secp256k1 range")
    return result | dict(network=network, validation="checksum_valid",
                         reason="Encoding, checksum, supported version, structure and scalar validated locally")


def _normalized(text):
    normalized, starts, ends = [], [], []
    for index, char in enumerate(text):
        part = unicodedata.normalize("NFKD", char)
        normalized.append(part)
        starts.extend([index] * len(part))
        ends.extend([index + 1] * len(part))
    return "".join(normalized), starts, ends


def _chains(text):
    chain = []
    for token in _WORD.finditer(text):
        gap = text[chain[-1].end():token.start()] if chain else ""
        if chain and (not gap or not gap.isspace() or len(gap) > 16):
            yield chain
            chain = []
        if token.group() in WORDS:
            chain.append(token)
        else:
            if chain:
                yield chain
            chain = []
    if chain:
        yield chain


def redact_text(value):
    """Suppress recognizable keys and phrase-shaped text, including URI encoding.

    Conservative: checksum failures and public examples are also sensitive.
    Never return a candidate prefix, suffix, hash or raw surrounding prose.
    """
    decoded = unquote(value)
    normalized = unicodedata.normalize("NFKD", decoded)
    if _KEY.search(normalized) or any(len(chain) >= 12 for chain in _chains(normalized)):
        return MASK
    return value


def _record(text, base, width, start, end, kind, result):
    return dict(value=text[start:end], canonical=text[start:end], offset=base + start * width,
                length=(end-start)*width, encoding="ascii" if width == 1 else "utf-16le",
                kind=kind, context="", amount="", confidence="format_valid",
                ambiguity="Occurrence does not prove ownership, use, control or wallet presence",
                **result)


def _find_text(text, base, width, mnemonics, keys, txids):
    # Keys/hex must be literal ASCII; compatibility normalization is for BIP-39.
    if keys:
        for match in _KEY.finditer(text):
            result = key_result(match.group())
            record = _record(text, base, width, *match.span(), "private_key", result)
            record["confidence"] = "format_valid" if result["validation"] == "checksum_valid" else "unvalidated_shape"
            yield record
    if txids:
        for match in _TX.finditer(text):
            before = text[max(0, match.start()-96):match.start()]
            label = _LABEL.search(before)
            context = label.group(1).lower() if label else "unlabeled_hex"
            chain = {"bitcoin_txid": "bitcoin-compatible-label",
                     "ethereum_transaction_hash": "ethereum-compatible-label"}.get(context, "unknown")
            record = _record(text, base, width, *match.span(), "transaction_id_candidate",
                             dict(currency="unknown", network=chain, format="hex-256",
                                  validation="candidate_only", reason="Text shape only; no transaction parsed or verified"))
            record.update(confidence="medium" if label else "low", context=context,
                          ambiguity="May be another hash, identifier, key or example; chain and transaction existence unverified",
                          supporting_context=({"label": context, "offset": base + (max(0, match.start()-96) + label.start()) * width,
                                               "length": (label.end()-label.start()) * width} if label else None))
            yield record
    if mnemonics:
        normalized, starts, ends = _normalized(text)
        for chain in _chains(normalized):
            for index in range(len(chain)):
                for length in LENGTHS:
                    selection = chain[index:index+length]
                    if len(selection) != length:
                        continue
                    value = normalized[selection[0].start():selection[-1].end()]
                    if not mnemonic_valid(value):
                        continue
                    start, end = starts[selection[0].start()], ends[selection[-1].end()-1]
                    record = _record(text, base, width, start, end, "mnemonic",
                                     dict(currency="unknown", network="unknown", format="BIP39-English",
                                          validation="checksum_valid", reason="English word list, allowed length and entropy checksum validated; NFKD/whitespace transcription"))
                    record.update(canonical=" ".join(value.split()), word_count=length,
                                  boundary_ambiguous=index > 0 or index+length < len(chain),
                                  ambiguity="Checksum collisions, ordinary prose and public examples possible; phrase boundaries and wallet use unverified")
                    hint = _EXAMPLE.search(normalized[max(0, selection[0].start()-96):selection[0].start()])
                    record["context"] = "example_or_test_vector" if hint and hint.group().lower().startswith(("example", "test")) else "phrase_text"
                    yield record


def find_artifacts(data, *, mnemonics=False, keys=False, txids=False):
    """Bounded contiguous buffer; caller handles overlap, limits and provenance."""
    if not isinstance(data, bytes) or len(data) > formats.MAX_BUFFER_BYTES:
        raise ValueError("Extended detector requires bytes in buffers no larger than 4 MiB")
    for run in _TEXT.finditer(data.decode("latin-1")):
        # Bytes >=128 are not ASCII. Unicode normalization is supported in wide text.
        if run.group().isascii():
            yield from _find_text(run.group(), run.start(), 1, mnemonics, keys, txids)
    # Either virtual byte alignment, with exact source spans after normalization.
    for alignment in (0, 1):
        size = (len(data)-alignment)//2*2
        text = data[alignment:alignment+size].decode("utf-16le", errors="replace")
        for run in _TEXT.finditer(text):
            yield from _find_text(run.group(), alignment+run.start()*2, 2, mnemonics, keys, txids)
