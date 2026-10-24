"""Monero public documentation vectors and synthetic format/scan fixtures.

Documentation examples: Monero Community (MIT); notices in LICENSE.
The generated payloads are arbitrary test bytes, not private keys or wallets.
"""
import builtins
import hashlib
import unittest
from unittest.mock import patch

from Crypto.Hash import keccak
from test_formats import BTC, ETH, XRP, detect, formats
from test_scanner import make_plugin, render, summary, findings, scanner


STANDARD = '4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge'
INTEGRATED = '4LL9oSLmtpccfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2bYXZKKQePHES9khPK'
STANDARD_RAW = bytes.fromhex('12eda9fe8dfcdd25d5430ea64229d04f6b41b2e5a1587c29cd499a63eb79d117113076a02b73d130fb904c9e91075fcd16f735c6850dfadb125eb826d96a113f09a57120a3')


def encode(raw):
    """Independent fixture encoder; production implements decoding only."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    widths = (0, 2, 3, 5, 6, 7, 9, 10, 11)
    result = ''
    for offset in range(0, len(raw), 8):
        block = raw[offset:offset + 8]
        number = int.from_bytes(block, 'big')
        digits = ''
        while number:
            number, digit = divmod(number, 58)
            digits = alphabet[digit] + digits
        result += digits.rjust(widths[len(block)], '1')
    return result


def synthetic(prefix, integrated=False, fill=None):
    payload = bytes([prefix]) + (bytes(range(64)) if fill is None else bytes([fill]) * 64)
    if integrated:
        payload += bytes(range(8))
    return encode(payload + keccak.new(digest_bits=256, data=payload).digest()[:4])


class MoneroTests(unittest.TestCase):
    def patch(self, target, name, value):
        patcher = patch.object(target, name, value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_published_standard_and_integrated_vectors(self):
        self.assertEqual(encode(STANDARD_RAW), STANDARD)
        for address, kind in ((STANDARD, 'standard'), (INTEGRATED, 'integrated')):
            row, = detect(address, {'XMR'})
            self.assertEqual(row['validation'], 'checksum_valid')
            self.assertEqual(row['format'], 'Monero-' + kind)
            self.assertEqual(row['network'], 'monero-mainnet-compatible')
            self.assertEqual(row['canonical'], address)
            self.assertIn('curve validity', row['reason'])

    def test_all_network_address_types_and_padding(self):
        for network, prefixes in (('mainnet', (18, 19, 42)), ('testnet', (53, 54, 63)), ('stagenet', (24, 25, 36))):
            for kind, prefix in zip(('standard', 'integrated', 'subaddress'), prefixes):
                for fill in (None, 0, 255):
                    with self.subTest(network=network, kind=kind, fill=fill):
                        address = synthetic(prefix, kind == 'integrated', fill)
                        row, = detect(address, {'XMR'})
                        self.assertEqual(row['validation'], 'checksum_valid')
                        self.assertEqual(row['format'], 'Monero-' + kind)
                        self.assertEqual(row['network'], 'monero-' + network + '-compatible')
                        self.assertEqual(row['canonical'], address)

    def test_bad_checksums_remain_candidates_and_sha3_is_not_keccak(self):
        for address in (STANDARD, INTEGRATED, synthetic(42)):
            corrupted = address[:-1] + ('1' if address[-1] != '1' else '2')
            row, = detect(corrupted, {'XMR'})
            self.assertEqual(row['validation'], 'checksum_invalid')
            self.assertEqual(row['value'], corrupted)
        payload = STANDARD_RAW[:-4]
        row, = detect(encode(payload + hashlib.sha3_256(payload).digest()[:4]), {'XMR'})
        self.assertEqual(row['validation'], 'checksum_invalid')

    def test_wrong_type_length_unknown_prefix_and_block_overflow(self):
        values = (synthetic(18, True), synthetic(19), synthetic(20),
                  STANDARD[:11] + 'z' * 11 + STANDARD[22:], STANDARD[:-7] + 'z' * 7)
        for value in values:
            with self.subTest(value=value):
                row, = detect(value, {'XMR'})
                self.assertEqual(row['validation'], 'malformed')

    def test_invalid_alphabet_lengths_and_token_boundaries(self):
        for address in (STANDARD, INTEGRATED):
            for value in (address[:-1], address + '1', 'x' + address, address + '_',
                          address[:40] + '0' + address[41:], address[:40] + 'O' + address[41:]):
                with self.subTest(value=value):
                    self.assertFalse(detect(value, {'XMR'}))
        self.assertFalse(detect('monero wallet XMR ' + 'f' * 64, {'XMR'}))

    def test_currency_filter_no_cross_classification_or_dependency_leak(self):
        mixed = ' '.join((STANDARD, BTC, ETH, XRP))
        self.assertEqual([r['currency'] for r in detect(mixed, {'XMR'})], ['XMR'])
        self.assertEqual([r['currency'] for r in detect(mixed, {'BTC', 'ETH', 'XRP'})], ['BTC', 'ETH', 'XRP'])
        original_import = builtins.__import__
        def no_crypto(name, *args, **kwargs):
            if name.startswith('Crypto'):
                raise ImportError('synthetic missing dependency')
            return original_import(name, *args, **kwargs)
        with patch.object(builtins, '__import__', no_crypto):
            with self.assertRaisesRegex(ImportError, 'pycryptodome'):
                formats.check_dependencies({'XMR'})
            with self.assertRaisesRegex(ImportError, 'pycryptodome'):
                detect(STANDARD, {'XMR'})
            self.assertFalse(detect(STANDARD, {'BTC'}))
            row, = detect('bitcoin:' + STANDARD, {'BTC'})
            self.assertEqual(row['validation'], 'malformed')

    def test_encodings_exact_offsets_context_and_plain_uri_address_only(self):
        for encoding, width in (('ascii', 1), ('utf-16le', 2)):
            for prefix in (b'', b'\xff'):
                text = '"recipient": "' + STANDARD + '" monero:' + INTEGRATED + '?tx_amount=1'
                rows = detect(text, {'XMR'}, encoding, prefix)
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]['context'], 'field:recipient')
                for row, address in zip(rows, (STANDARD, INTEGRATED)):
                    self.assertEqual(row['offset'], len(prefix) + text.index(address) * width)
                    self.assertEqual(row['length'], len(address) * width)
                    self.assertEqual(row['kind'], 'address')
                    self.assertEqual(row['amount'], '')

    def test_scanner_xmr_and_all_preserve_chunk_provenance_and_artifacts(self):
        for currency in ('xmr', 'all'):
            for encoding in ('ascii', 'utf-16le'):
                for address in (STANDARD, INTEGRATED, synthetic(42)):
                    with self.subTest(currency=currency, encoding=encoding, address=address):
                        token = address.encode(encoding)
                        start = scanner.CryptoMem.CHUNK_BYTES - len(token) // 2
                        data = b' ' * start + token + b' ' * scanner.CryptoMem.CHUNK_BYTES
                        plugin = make_plugin(self, data, currency=currency)
                        with patch('socket.socket.connect', side_effect=AssertionError('network')), patch('subprocess.Popen', side_effect=AssertionError('process')):
                            rows = render(plugin)
                        self.assertEqual(len(rows), 1)
                        self.assertEqual(rows[0]['Offset'], start)
                        self.assertEqual(rows[0]['PID'], 42)
                        self.assertEqual(rows[0]['Currency'], 'XMR')
                        self.assertEqual(rows[0]['ByteLength'], len(token))
                        self.assertEqual(rows[0]['Validation'], 'checksum_valid')
                        self.assertEqual(findings()[0]['value'], address)
                        self.assertEqual(summary()['completion_state'], 'complete')
                        self.assertEqual(summary()['bytes_evaluated'], len(data))

    def test_xmr_missing_dependency_fails_before_any_memory_read(self):
        plugin = make_plugin(self, b'ordinary memory', currency='xmr')
        with patch.object(scanner.formats, '_keccak_module', side_effect=ImportError('missing Monero checksum dependency')):
            with self.assertRaisesRegex(ImportError, 'missing Monero'):
                render(plugin)
        self.assertEqual(summary()['bytes_read'], 0)
        self.assertEqual(summary()['completion_state'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
