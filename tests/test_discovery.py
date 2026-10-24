"""Real CLI discovery and corrupt-input checks; no Windows memory fixture."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DiscoveryTests(unittest.TestCase):
    def test_external_namespace_preserves_native_catalog(self):
        code = '''
import json, sys
from volatility3 import framework, plugins
from volatility3.framework import constants
if len(sys.argv) > 1:
    plugins.__path__ = [sys.argv[1]] + constants.PLUGINS_PATH
failures = framework.import_files(plugins, True)
print(json.dumps({'names': sorted(framework.list_plugins()), 'failures': failures}))
'''
        def catalog(*args):
            result = subprocess.run([sys.executable, '-I', '-c', code, *args],
                                    capture_output=True, text=True, timeout=60, check=True)
            return json.loads(result.stdout)
        before, after = catalog(), catalog(str(ROOT / 'plugins'))
        self.assertEqual(set(after['names']) - set(before['names']),
                         {'windows.cryptomem.CryptoMem'})
        self.assertTrue(set(before['names']) <= set(after['names']))
        self.assertEqual(set(before['failures']), set(after['failures']))
        self.assertIn('windows.pslist.PsList', after['names'])

    def test_cli_help_and_corrupt_input_do_not_need_mcp(self):
        command = [sys.executable, '-I', '-c', 'import sys; sys.argv[0] = "vol"; from volatility3.cli import main; main()',
                   '--offline', '-p', str(ROOT / 'plugins')]
        help_result = subprocess.run(command + ['windows.cryptomem.CryptoMem', '--pid', '42', '-h'],
                                     capture_output=True, text=True, timeout=60)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn('--pid', help_result.stdout)
        self.assertIn('--max-scan-bytes', help_result.stdout)
        self.assertIn('xmr', help_result.stdout)
        self.assertNotIn('--api-key', help_result.stdout)
        with tempfile.TemporaryDirectory(prefix='cryptomem-invalid-') as temporary:
            root = Path(temporary)
            image = root / 'invalid.raw'
            original = b'SYNTHETIC invalid acquisition, not a Windows kernel' * 100
            image.write_bytes(original)
            output = root / 'outputs'; output.mkdir()
            (root / 'cache').mkdir()
            result = subprocess.run(command + ['--cache-path', str(root / 'cache'),
                '-f', str(image), '-o', str(output), '-r', 'json',
                'windows.cryptomem.CryptoMem', '--pid', '42'],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Unsatisfied requirement', result.stdout + result.stderr)
            self.assertEqual(image.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
