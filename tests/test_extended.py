"""Public vectors/generated memory only. No real capture or recovered secret."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from volatility3.cli import CommandLine, text_renderer
from volatility3.framework.layers.physical import BufferDataLayer
from test_scanner import CaptureFile, make_plugin, render, FaultLayer, BTC
import test_scanner as windows_fixture
from test_linux import make_plugin as linux_plugin
from test_mac import make_plugin as mac_plugin
from volatility3.plugins.windows import cryptomem_extended as ext

PHRASE = "abandon " * 11 + "about"  # BIP-39 public zero-entropy example.
XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"  # BIP-32 vector 1.


def encode(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, result = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        result = ext.formats._BTC_ALPHABET[digit] + result
    return "1" * (len(data)-len(data.lstrip(b"\0"))) + result


WIF = encode(b"\x80" + (1).to_bytes(32, "big") + b"\1")


def phrase_for_entropy(length):
    entropy = bytes(length)
    checksum = length // 4
    value = (int.from_bytes(entropy, "big") << checksum) | (hashlib.sha256(entropy).digest()[0] >> (8-checksum))
    words = list(ext.WORDS)
    count = (length*8+checksum)//11
    return " ".join(words[(value >> (11*i)) & 2047] for i in reversed(range(count)))


class ExtendedFormatTests(unittest.TestCase):
    def test_pinned_list_all_phrase_lengths_and_bad_checksums(self):
        ext.check_wordlist()
        for size in (16,20,24,28,32):
            phrase = phrase_for_entropy(size)
            self.assertTrue(ext.mnemonic_valid(phrase))
            self.assertFalse(ext.mnemonic_valid(phrase.rsplit(" ",1)[0] + " abandon"))
        for phrase in ("abandon "*12, "abandon "*10+"about", PHRASE.upper(), PHRASE+" zzz", "ordinary prose "*12):
            self.assertFalse(ext.mnemonic_valid(phrase))

    def test_nfkd_whitespace_and_exact_wide_source_spans(self):
        fullwidth = "".join(chr(ord(c)+0xFEE0) if "a" <= c <= "z" else "\u3000" for c in PHRASE)
        self.assertTrue(ext.mnemonic_valid(fullwidth))
        for text in (PHRASE, PHRASE.replace(" ","\t\n"), fullwidth):
            data = b"!" + text.encode("utf-16le") + b"\0\0"
            row, = ext.find_artifacts(data, mnemonics=True)
            self.assertEqual((row['offset'],row['length'],row['value']), (1,len(text)*2,text))
            self.assertEqual(row['canonical'],PHRASE)
        self.assertEqual(list(ext.find_artifacts(PHRASE.upper().encode(), mnemonics=True)), [])

    def test_phrase_boundaries_examples_and_prose_are_ambiguous(self):
        rows = list(ext.find_artifacts(("example: " + PHRASE + " abandon").encode(), mnemonics=True))
        self.assertTrue(rows[0]['boundary_ambiguous'])
        self.assertEqual(rows[0]['context'],'example_or_test_vector')
        self.assertIn('ordinary prose', rows[0]['ambiguity'])
        self.assertEqual(list(ext.find_artifacts(("prefix"+PHRASE).encode(), mnemonics=True)), [])
        self.assertEqual(list(ext.find_artifacts((" ".join(PHRASE.split()[:6])+"!"+" ".join(PHRASE.split()[6:])).encode(), mnemonics=True)), [])

    def test_wif_versions_markers_checksums_and_scalar_constraints(self):
        for version in (0x80,0xEF):
            for marker in (b"",b"\1"):
                key = encode(bytes([version])+(1).to_bytes(32,'big')+marker)
                self.assertEqual(ext.key_result(key)['validation'],'checksum_valid')
        for scalar in (0,ext.ORDER,2**256-1):
            self.assertEqual(ext.key_result(encode(b'\x80'+scalar.to_bytes(32,'big')))['validation'],'malformed')
        for payload in (b'\x81'+bytes(31)+b'\1', b'\x80'+bytes(31)+b'\1\2', b'\x80'+bytes(31)):
            self.assertEqual(ext.key_result(encode(payload))['validation'],'malformed')
        self.assertEqual(ext.key_result(WIF[:-1]+('1' if WIF[-1]!='1' else '2'))['validation'],'checksum_invalid')
        self.assertEqual(ext.key_result('5'+'0'*50)['validation'],'malformed')

    def test_bip32_public_vector_and_structure(self):
        self.assertEqual(ext.key_result(XPRV)['validation'],'checksum_valid')
        root = ext.formats._base58(XPRV,ext.formats._BTC_ALPHABET)[:-4]
        self.assertEqual(ext.key_result(encode(bytes.fromhex('04358394')+root[4:]))['validation'],'checksum_valid')
        for start, replacement in ((0,bytes.fromhex('0488b21e')),(5,b'\1'),(9,b'\1'),(45,b'\1'),(46,bytes(32)),(46,ext.ORDER.to_bytes(32,'big'))):
            payload = root[:start]+replacement+root[start+len(replacement):]
            self.assertEqual(ext.key_result(encode(payload))['validation'],'malformed')
        self.assertEqual(list(ext.find_artifacts(bytes(32), keys=True)), [])
        self.assertEqual(list(ext.find_artifacts(('a'+WIF+'b '+XPRV+'z').encode(), keys=True)), [])

    def test_txid_is_candidate_only_and_support_is_structured(self):
        value = 'ab'*32
        for prefix,confidence,network in (('', 'low','unknown'),('txid: ', 'medium','unknown'),('bitcoin_txid="','medium','bitcoin-compatible-label')):
            row, = ext.find_artifacts((prefix+value).encode(), txids=True)
            self.assertEqual((row['confidence'],row['network'],row['validation']), (confidence,network,'candidate_only'))
            self.assertIn('another hash', row['ambiguity'])
            self.assertEqual(row['offset'],len(prefix))
            if prefix:
                self.assertEqual(row['supporting_context']['offset'],0)
        row, = ext.find_artifacts(('transaction_hash: 0x'+value).encode(), txids=True)
        self.assertEqual(row['network'],'unknown')
        self.assertEqual(list(ext.find_artifacts((value+'a').encode(), txids=True)), [])
        self.assertEqual(list(ext.find_artifacts(('block_hash: '+value).encode(), txids=True))[0]['confidence'],'low')
        self.assertEqual(list(ext.find_artifacts(value.encode())), [])


class ExtendedScannerTests(unittest.TestCase):
    patch = windows_fixture.ScannerTests.patch
    setUp = windows_fixture.ScannerTests.setUp
    def test_opt_in_adapters_boundaries_offsets_and_masking(self):
        for factory in (make_plugin,linux_plugin,mac_plugin):
            for value, option in ((PHRASE,'detect_mnemonics'), (WIF,'detect_private_keys'), (XPRV,'detect_private_keys'), ('cd'*32,'detect_txids')):
                for encoding in ('ascii','utf-16le'):
                    for split in (1,len(value)//2,len(value)-1):
                        token = value.encode(encoding)
                        start = 65536-split
                        data = b' '*start+token+b' '*6000
                        rows = render(factory(self,data,**{option:True},currency='btc'))
                        self.assertEqual(len(rows),1)
                        self.assertEqual((rows[0]['Offset'],rows[0]['ByteLength']), (start,len(token)))
                        outputs = b''.join(CaptureFile.outputs.values())
                        if option != 'detect_txids':
                            self.assertNotIn(value.encode(),outputs)
                            self.assertEqual(rows[0]['Value'],ext.MASK)
                        self.assertNotIn('cryptomem-findings.jsonl',CaptureFile.outputs)
                        self.assertEqual(json.loads(CaptureFile.outputs['cryptomem-scan-summary-v2.json'])['schema_version'],2)

    def test_separate_mappings_unreadable_gaps_and_limits(self):
        for factory in (make_plugin,linux_plugin,mac_plugin):
            for value,flag in ((PHRASE,'detect_mnemonics'), (WIF,'detect_private_keys'), ('ef'*32,'detect_txids')):
                token = value.encode(); midpoint = len(token)//2
                ranges = [(0,midpoint-1),(midpoint,len(token)-1)] if factory is make_plugin else [(0,midpoint),(midpoint,len(token))]
                self.assertEqual(render(factory(self,token,ranges=ranges,**{flag:True})),[])
            with self.assertRaisesRegex(Exception,'Unreadable'):
                render(factory(self,b' '*65530+PHRASE.encode()+b' '*70000,layer_class=FaultLayer,detect_mnemonics=True))
            self.assertNotIn(PHRASE.encode(),b''.join(CaptureFile.outputs.values()))
            for kwargs in ({'max_results':1},{'max_scan_bytes':6000}):
                with self.assertRaisesRegex(Exception,'limit'):
                    render(factory(self,(WIF+' '+WIF+' ').encode()+b' '*9000,detect_private_keys=True,**kwargs))
                summary = json.loads(CaptureFile.outputs['cryptomem-scan-summary-v2.json'])
                self.assertEqual(summary['completion_state'],'incomplete')

    def test_empty_invalid_options_and_default_does_not_enable_detectors(self):
        self.assertEqual(render(make_plugin(self,(PHRASE+' '+WIF+' '+XPRV).encode(),currency='btc')), [])
        self.assertEqual(render(make_plugin(self,b'plain',detect_mnemonics=True)), [])
        for kwargs in ({'extract_secrets':True},{'extract_secrets':True,'detect_txids':True},{'detect_mnemonics':1},{'extract_secrets':'yes'}):
            with self.assertRaises(ValueError):
                make_plugin(self,b'plain',**kwargs)

    def test_all_renderers_and_interruption_never_emit_secrets(self):
        renderers = (text_renderer.JsonRenderer,text_renderer.CSVRenderer,text_renderer.QuickTextRenderer,text_renderer.PrettyTextRenderer)
        for renderer in renderers:
            plugin = make_plugin(self,(PHRASE+' '+WIF).encode(),detect_mnemonics=True,detect_private_keys=True)
            output = io.StringIO()
            with redirect_stdout(output):
                renderer().render(plugin.run())
            for secret in (PHRASE,WIF):
                self.assertNotIn(secret,output.getvalue())
                self.assertNotIn(secret.encode(),b''.join(CaptureFile.outputs.values()))
        plugin = make_plugin(self,(PHRASE+' '+WIF).encode(),detect_mnemonics=True,detect_private_keys=True)
        generator = plugin._generator(); next(generator); generator.close()
        self.assertEqual(json.loads(CaptureFile.outputs['cryptomem-scan-summary-v2.json'])['completion_state'],'incomplete')
        self.assertNotIn(PHRASE.encode(),b''.join(CaptureFile.outputs.values()))

    def test_exception_text_is_not_logged_or_saved(self):
        class LeakingLayer(BufferDataLayer):
            def read(self,*args,**kwargs):
                raise RuntimeError(PHRASE+' '+WIF)
        plugin = make_plugin(self,b'plain',layer_class=LeakingLayer,detect_mnemonics=True)
        with self.assertRaises(Exception) as error:
            render(plugin)
        for secret in (PHRASE,WIF):
            self.assertNotIn(secret,str(error.exception))
            self.assertNotIn(secret.encode(),b''.join(CaptureFile.outputs.values()))

    @unittest.skipUnless(os.name=='posix','Extraction requires private POSIX fd')
    def test_explicit_extraction_only_through_private_configured_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = CommandLine.__new__(CommandLine); cli.output_dir=directory
            plugin = make_plugin(self,(PHRASE+' '+WIF).encode(),detect_mnemonics=True,detect_private_keys=True,extract_secrets=True)
            plugin.set_open_method(cli.file_handler_class_factory())
            rows = render(plugin)
            self.assertTrue(all(row['Value']==ext.MASK for row in rows))
            path = Path(directory)/'cryptomem-secrets-v1.jsonl'
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            recovered = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual({row['value'] for row in recovered},{PHRASE,WIF})
            for ordinary in Path(directory).glob('*'):
                if ordinary != path:
                    self.assertNotIn(PHRASE,ordinary.read_text())
                    self.assertNotIn(WIF,ordinary.read_text())
        plugin = make_plugin(self,PHRASE.encode(),detect_mnemonics=True,extract_secrets=True)
        with self.assertRaisesRegex(Exception,'Extended scan failed'):
            render(plugin)  # CaptureFile has no private regular fd: fail closed.
        self.assertNotIn(PHRASE.encode(),b''.join(CaptureFile.outputs.values()))

    def test_secret_in_payment_message_is_masked_in_address_only_scan(self):
        uri = 'bitcoin:'+BTC.decode()+'?message='+WIF
        rows = render(make_plugin(self,uri.encode()))
        self.assertNotIn(WIF,json.dumps(rows))
        self.assertNotIn(WIF.encode(),b''.join(CaptureFile.outputs.values()))


if __name__ == '__main__':
    unittest.main()
