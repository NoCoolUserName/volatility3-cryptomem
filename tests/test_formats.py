"""Synthetic byte fixtures and published format vectors; no real memory images.

BIP-350 vectors (Pieter Wuille, BSD-2-Clause), ERC-55 examples (Vitalik
Buterin/Alex Van de Sande, CC0), XRPL documented classic-address examples.
See THIRD_PARTY_NOTICES.md. No fixture represents wallet possession or control.
"""
import builtins
import hashlib
import importlib.util
from pathlib import Path
import socket
import urllib.request
from urllib.parse import quote
import unittest
import unittest.mock
_SPEC = importlib.util.spec_from_file_location('cryptomem_formats_test', Path(__file__).parents[1] / 'plugins/windows/cryptomem_formats.py')
formats = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(formats)
BTC = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
ETH = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
XRP = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'
ALL = {'BTC', 'ETH', 'XRP'}
VALID_SEGWIT = ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', 'BC1SW50QGDZ25J', 'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', 'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0']
INVALID_SEGWIT = ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd', 'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf', 'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh', 'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47', 'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4', 'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R', 'bc1pw5dgrnzv', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav', 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf', 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j', 'bc1gmk9yu']

def detect(value, currencies=None, encoding='ascii', prefix=b''):
    return list(formats.find_artifacts(prefix + value.encode(encoding), currencies if currencies is not None else ALL))

class FormatTests(unittest.TestCase):

    def test_bip350_all_native_witness_valid_vectors(self):
        for value in VALID_SEGWIT:
            with self.subTest(value=value):
                result, = detect(value)
                self.assertEqual(result['validation'], 'checksum_valid')
                self.assertEqual(result['canonical'], value.lower())
                self.assertTrue(result['network'].endswith('-compatible'))

    def test_bip350_native_witness_invalid_vectors(self):
        for value in INVALID_SEGWIT:
            with self.subTest(value=value):
                result, = detect(value)
                self.assertIn(result['validation'], {'checksum_invalid', 'malformed'})

    def test_unknown_witness_network_not_recognized(self):
        self.assertFalse(detect('tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut'))

    def test_base58check_genesis_and_xrp_specification_vectors(self):
        results = detect(BTC + ' ' + XRP + ' rrrrrrrrrrrrrrrrrrrrrhoLvTp')
        self.assertEqual([row['validation'] for row in results], ['checksum_valid'] * 3)
        self.assertEqual(results[0]['format'], 'Base58Check-P2PKH')
        self.assertEqual(results[1]['network'], 'unspecified')
        self.assertEqual(results[1]['canonical'], XRP)

    def test_base58_payload_and_network_versions(self):
        for version, expected in [(0, 'mainnet'), (5, 'mainnet'), (111, 'testnet'), (196, 'testnet')]:
            with self.subTest(version=version, expected=expected):
                payload = bytes([version]) + bytes(range(20))
                checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                integer = int.from_bytes(payload + checksum, 'big')
                alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                encoded = ''
                while integer:
                    integer, index = divmod(integer, 58)
                    encoded = alphabet[index] + encoded
                raw = payload + checksum
                encoded = '1' * (len(raw) - len(raw.lstrip(b'\x00'))) + encoded
                row, = detect(encoded)
                self.assertEqual(row['validation'], 'checksum_valid')
                self.assertIn(expected, row['network'])

    def test_checksum_corruption_remains_a_candidate(self):
        for value in [BTC[:-1] + 'b', XRP[:-1] + 'a']:
            with self.subTest(value=value):
                result, = detect(value)
                self.assertEqual(result['validation'], 'checksum_invalid')
                self.assertEqual(result['value'], value)

    def test_invalid_base58_payload_lengths(self):
        for value in ['1' * 26, 'r' * 26, '1' * 35, 'r' * 35]:
            with self.subTest(value=value):
                result, = detect(value)
                self.assertEqual(result['validation'], 'malformed')

    def test_erc55_mixed_case_vectors(self):
        for value in [ETH, '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']:
            with self.subTest(value=value):
                result, = detect(value)
                self.assertEqual(result['validation'], 'checksum_valid')
                self.assertEqual(result['canonical'], value.lower())
                self.assertEqual(result['network'], 'unspecified')

    def test_erc55_uniform_case_is_conservatively_format_only(self):
        for value in ['0x52908400098527886E0F7030069857D2E4169EE7', '0x8617E340B3D01FA5F11F306F4090FD50E238070D', '0xde709f2102306220921060314715629080e2fb77', '0x27b1fdb04752bbc536007a920d24acb045561c26', '0x' + '0' * 40]:
            with self.subTest(value=value):
                result, = detect(value)
                self.assertEqual(result['validation'], 'format_only')
                self.assertIn('chain unknown', result['reason'])

    def test_erc55_bad_mixed_case_is_explicitly_invalid(self):
        result, = detect(ETH.replace('5aAe', '5AAe'))
        self.assertEqual(result['validation'], 'checksum_invalid')

    def test_encodings_alignments_and_exact_byte_offsets(self):
        for encoding, width in [('ascii', 1), ('utf-16le', 2)]:
            for prefix in [b'', b'\xff', b'\xff\xff', b'\x00\xd8']:
                with self.subTest(encoding=encoding, width=width, prefix=prefix):
                    value = '"recipient": "' + BTC + '"'
                    row, = detect(value, encoding=encoding, prefix=prefix)
                    self.assertEqual(row['offset'], len(prefix) + len('"recipient": "') * width)
                    self.assertEqual(row['length'], len(BTC) * width)
                    self.assertEqual(row['encoding'], encoding)
                    self.assertEqual(row['context'], 'field:recipient')
                    data = prefix + value.encode(encoding)
                    self.assertEqual(data[row['offset']:row['offset'] + row['length']].decode(encoding), BTC)

    def test_no_substrings_inside_longer_tokens(self):
        for value in [BTC, ETH, XRP, VALID_SEGWIT[0]]:
            for surround in [('x', ''), ('', 'x'), ('_', ''), ('', '_')]:
                with self.subTest(value=value, surround=surround):
                    self.assertFalse(any((row['value'] == value for row in detect(surround[0] + value + surround[1]))))

    def test_wide_run_never_joins_non_ascii_or_unreadable_bytes(self):
        broken = BTC[:15].encode('utf-16le') + b'\x01\xff' + BTC[15:].encode('utf-16le')
        self.assertFalse(list(formats.find_artifacts(broken, ALL)))

    def test_every_distinct_occurrence_is_preserved(self):
        rows = detect(BTC + ' ' + BTC)
        self.assertEqual([row['offset'] for row in rows], [0, len(BTC) + 1])

    def test_bitcoin_uri_subset_with_exact_address_and_amount(self):
        uri = f'BITCOIN:{BTC}?AMOUNT=0.001&label=Test%20recipient&message=Example'
        request, address = detect(uri)
        self.assertEqual(request['kind'], 'payment_request')
        self.assertEqual(request['validation'], 'checksum_valid')
        self.assertEqual(request['amount'], '0.001')
        self.assertEqual(request['value'], uri)
        self.assertEqual(address['kind'], 'address')
        self.assertEqual(address['offset'], 8)
        self.assertEqual(address['context'], 'payment_request_text')
        self.assertIn('requested, not paid', request['reason'])

    def test_ethereum_uri_explicit_chain_and_atomic_amount(self):
        request, address = detect(f'ethereum:pay-{ETH}@11155111?value=2.014e18&gas=21000')
        self.assertEqual(request['validation'], 'checksum_valid')
        self.assertEqual(request['network'], 'declared-chain-id:11155111')
        self.assertEqual(request['amount'], '2.014e18')
        self.assertEqual(address['network'], 'unspecified')
        self.assertEqual(address['offset'], 13)

    def test_malformed_bitcoin_uris_are_not_validated(self):
        for suffix in ['?amount=-1', '?amount=0.000000001', '?amount=1e8', '?amount=1&amount=2', '?label=%zz', '?label=%ff', '?label=%00', '?', '?amount=', '?label']:
            with self.subTest(suffix=suffix):
                request = detect(f'bitcoin:{BTC}{suffix}')[0]
                self.assertEqual(request['validation'], 'malformed')
                self.assertEqual(request['amount'], '')

    def test_invalid_ethereum_numeric_fields(self):
        for value in ['-1', '1.2', '1.23e1', '1e999', 'NaN', '1e-1', str(2 ** 256)]:
            with self.subTest(value=value):
                request = detect(f'ethereum:{ETH}?value={value}')[0]
                self.assertEqual(request['validation'], 'malformed')

    def test_raw_forbidden_query_characters_preserve_malformed_request(self):
        for encoding in ('ascii', 'utf-16le'):
            for label in ('{label}', '[label]', 'a|b', 'a^b', 'a`b'):
                with self.subTest(encoding=encoding, label=label):
                    uri = f'bitcoin:{BTC}?label={label}'
                    request, address = detect(uri, encoding=encoding)
                    self.assertEqual(request['value'], uri)
                    self.assertEqual(request['validation'], 'malformed')
                    self.assertIn('raw query character', request['reason'])
                    self.assertEqual(address['value'], BTC)
                    self.assertEqual(address['validation'], 'checksum_valid')

    def test_percent_encoded_label_characters_and_unicode_remain_supported(self):
        for label in ('{label}', '[label]', 'a|b', 'a^b', 'a`b', 'two words', '\u2603'):
            with self.subTest(label=label):
                uri = f'bitcoin:{BTC}?label={quote(label, safe="")}'
                request, address = detect(uri)
                self.assertEqual(request['value'], uri)
                self.assertEqual(request['validation'], 'checksum_valid')
                self.assertEqual(address['value'], BTC)

    def test_query_allows_rfc3986_punctuation_without_decoding_plus(self):
        uri = f'bitcoin:{BTC}?label=a/b?c:@!$()*+,;=._~-'
        request, address = detect(uri)
        self.assertEqual(request['validation'], 'checksum_valid')
        self.assertEqual(request['value'], uri)
        self.assertEqual(address['value'], BTC)
        self.assertEqual(formats._query('label=a+b', True), {'label': 'a+b'})

    def test_percent_encoded_unicode_numbers_and_spaces_are_rejected(self):
        values = ['\u0661', '1.\u0662', '1e\u0662', '\uff11', '1\u00a0', '1\u2009', '\u20031']
        fields = [('bitcoin', BTC, 'amount')] + [
            ('ethereum', ETH, key) for key in ('value', 'gas', 'gasLimit', 'gasPrice')
        ]
        for scheme, target, key in fields:
            for value in values:
                with self.subTest(scheme=scheme, key=key, value=value):
                    uri = f'{scheme}:{target}?{key}={quote(value, safe="")}'
                    request, address = detect(uri)
                    self.assertEqual(request['validation'], 'malformed')
                    self.assertEqual(request['amount'], '')
                    self.assertEqual(address['kind'], 'address')
                    self.assertEqual(address['value'], target)
                    self.assertEqual(address['validation'], 'checksum_valid')
                    self.assertEqual(address['offset'], len(scheme) + 1)

    def test_unsupported_uri_features_are_explicit(self):
        for uri in ['ethereum:some-name.eth?value=1', f'ethereum:{ETH}/transfer?address={ETH}&uint256=1', f'bitcoin:{BTC}?req-extra=1', f'bitcoin:{BTC}?r=https://example.invalid/payment', f'bitcoin:{BTC}?lightning=lnbc1example', f'bitcoin://{BTC}', f'ethereum:{ETH}#anything']:
            with self.subTest(uri=uri):
                request = detect(uri)[0]
                self.assertEqual(request['kind'], 'payment_request')
                self.assertEqual(request['validation'], 'unsupported')

    def test_unsupported_request_still_preserves_embedded_address_evidence(self):
        rows = detect(f'ethereum:{ETH}/transfer?address={ETH}&uint256=1')
        self.assertEqual(rows[0]['validation'], 'unsupported')
        self.assertEqual([row['kind'] for row in rows[1:]], ['address', 'address'])
        self.assertTrue(all((row['context'] == 'payment_request_text' for row in rows[1:])))

    def test_long_uri_is_not_silently_truncated(self):
        for encoding in ['ascii', 'utf-16le']:
            with self.subTest(encoding=encoding):
                rows = detect(f'bitcoin:{BTC}?label=' + 'a' * 3000, encoding=encoding)
                self.assertFalse(any((row['kind'] == 'payment_request' for row in rows)))
                self.assertTrue(all((row['length'] <= formats.MAX_ARTIFACT_BYTES for row in rows)))

    def test_wide_maximum_uri_bound(self):
        prefix = f'ethereum:{ETH}?value='
        uri = prefix + '0' * (2048 - len(prefix))
        request = detect(uri, encoding='utf-16le')[0]
        self.assertEqual(request['length'], formats.MAX_ARTIFACT_BYTES)

    def test_absent_unsupported_and_unrelated_artifacts(self):
        self.assertFalse(detect('A wallet word is not a wallet; ' + 'a' * 64 + ' ' + '0x' + 'b' * 64))
        self.assertFalse(detect(BTC, currencies={'ETH'}))
        self.assertFalse(detect(BTC, currencies=set()))

    def test_invalid_currency_filters(self):
        for currencies in [{'DOGE'}, {'btc'}, ['BTC'], 'BTC']:
            with self.subTest(currencies=currencies):
                with self.assertRaisesRegex(ValueError, 'currencies'):
                    list(formats.find_artifacts(b'', currencies))

    def test_detector_buffer_type_and_size_limits(self):
        for data in ['text', bytearray(), b'x' * (formats.MAX_BUFFER_BYTES + 1)]:
            with self.assertRaisesRegex(ValueError, '4 MiB'):
                list(formats.find_artifacts(data, ALL))

    def test_missing_dependency_fails_before_scan_and_filtered_currencies_work(self):
        original_import = builtins.__import__

        def no_crypto(name, *args, **kwargs):
            if name.startswith('Crypto'):
                raise ImportError('synthetic missing dependency')
            return original_import(name, *args, **kwargs)
        patcher1 = unittest.mock.patch.object(builtins, '__import__', no_crypto)
        patcher1.start()
        self.addCleanup(patcher1.stop)
        with self.assertRaisesRegex(ImportError, 'pycryptodome==3.23.0'):
            formats.check_dependencies({'ETH'})
        with self.assertRaisesRegex(ImportError, 'pycryptodome==3.23.0'):
            detect(ETH)
        formats.check_dependencies({'BTC', 'XRP'})
        self.assertEqual(detect(BTC, currencies={'BTC'})[0]['validation'], 'checksum_valid')
        self.assertEqual(detect(XRP, currencies={'XRP'})[0]['validation'], 'checksum_valid')
        self.assertFalse(detect(ETH + f' ethereum:{ETH}', currencies={'BTC'}))

    def test_detector_is_offline_even_for_uris_and_recovered_endpoints(self):

        def reject_network(*args, **kwargs):
            raise AssertionError('network access must never occur')
        patcher1 = unittest.mock.patch.object(socket, 'socket', reject_network)
        patcher1.start()
        self.addCleanup(patcher1.stop)
        patcher2 = unittest.mock.patch.object(urllib.request, 'urlopen', reject_network)
        patcher2.start()
        self.addCleanup(patcher2.stop)
        rows = detect(f'bitcoin:{BTC}?r=https://example.invalid/payment ethereum:{ETH} {XRP}')
        self.assertTrue(rows)
        self.assertEqual(rows[0]['validation'], 'unsupported')
if __name__ == '__main__':
    unittest.main()
