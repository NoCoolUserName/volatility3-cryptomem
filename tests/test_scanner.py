"""Synthetic process/VAD tests using real Volatility layers and renderers.

These tests do not establish end-to-end accuracy on a real Windows memory image.
"""
import importlib
import inspect
import io
import json
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stdout
from volatility3.cli import text_renderer
from volatility3.framework import contexts, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.plugins import windows
PLUGIN_DIR = Path(__file__).resolve().parents[1] / 'plugins' / 'windows'
if str(PLUGIN_DIR) not in windows.__path__:
    windows.__path__.insert(0, str(PLUGIN_DIR))
scanner = importlib.import_module('volatility3.plugins.windows.cryptomem')
# Dependency initialization may run the trusted platform `file` utility on macOS.
# The scan itself is guarded against subprocess and network access in setUp.
scanner.formats.check_dependencies({'ETH'})
BTC = b'1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
ETH = b'0x52908400098527886E0F7030069857D2E4169EE7'

class CaptureFile(interfaces.plugins.FileHandlerInterface):
    outputs = {}

    def __init__(self, filename):
        super().__init__(filename)
        self.buffer = io.BytesIO()

    def write(self, data):
        return self.buffer.write(data)

    def flush(self):
        pass

    def close(self):
        if not self.closed:
            self.outputs[self.preferred_filename] = self.buffer.getvalue()
        super().close()

class FakeVad:

    def __init__(self, start, end):
        self.start, self.end = (start, end)

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

class FakeProcess:
    UniqueProcessId = 42
    ImageFileName = SimpleNamespace(vol=SimpleNamespace(count=16), cast=lambda *args, **kwargs: 'synthetic.exe')

    def __init__(self, ranges, layer='process'):
        self.ranges, self.layer = (ranges, layer)

    def add_process_layer(self):
        return self.layer

    def get_vad_root(self):
        return SimpleNamespace(traverse=lambda: (FakeVad(*pair) for pair in self.ranges))

def make_plugin(test, data, ranges=None, layer_class=BufferDataLayer, **config):
    context = contexts.Context()
    layer = layer_class(context, 'layers.process', 'process', data)
    context.layers.add_layer(layer)
    module = context.module('synthetic', 'process', 0)
    context.config['plugins.test.kernel'] = module.name
    context.config['plugins.test.pid'] = 42
    for name, value in config.items():
        if value is None:
            del context.config[f'plugins.test.{name}']
        else:
            context.config[f'plugins.test.{name}'] = value
    proc = FakeProcess(ranges if ranges is not None else [(0, len(data) - 1)])

    def processes(cls, passed_context, kernel_module_name):
        assert passed_context is context
        assert kernel_module_name == module.name
        return iter([proc])
    test.patch(scanner.pslist.PsList, 'list_processes', classmethod(processes))
    plugin = scanner.CryptoMem(context, 'plugins.test')
    CaptureFile.outputs = {}
    plugin.set_open_method(CaptureFile)
    return plugin

def render(plugin):
    output = io.StringIO()
    with redirect_stdout(output):
        text_renderer.JsonRenderer().render(plugin.run())
    return json.loads(output.getvalue())

def summary():
    return json.loads(CaptureFile.outputs['cryptomem-scan-summary.json'])

def findings():
    return [json.loads(line) for line in CaptureFile.outputs['cryptomem-findings.jsonl'].splitlines()]

class FaultLayer(BufferDataLayer):

    def read(self, offset, length, pad=False):
        assert pad is False
        if offset >= scanner.CryptoMem.CHUNK_BYTES:
            raise exceptions.InvalidAddressException(self.name, offset)
        return super().read(offset, length, pad=pad)

class ShortLayer(BufferDataLayer):

    def read(self, offset, length, pad=False):
        return super().read(offset, length, pad=pad)[:-1]

class ScannerTests(unittest.TestCase):

    def patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def setUp(self):

        def forbidden(*args, **kwargs):
            raise AssertionError('Scanner must not use the network or execute a process')
        self.patch(socket.socket, 'connect', forbidden)
        self.patch(subprocess, 'Popen', forbidden)

    def test_current_volatility_requirements_and_pslist_signature(self):
        reqs = {req.name: req for req in scanner.CryptoMem.get_requirements()}
        assert isinstance(reqs['kernel'], requirements.ModuleRequirement)
        assert isinstance(reqs['pid'], requirements.IntRequirement)
        assert reqs['pid'].optional is False
        assert reqs['pslist']._component is scanner.pslist.PsList
        assert 'kernel_module_name' in inspect.signature(scanner.pslist.PsList.list_processes).parameters

    def test_invalid_parameters(self):
        for config in [{'pid': None}, {'pid': 0}, {'pid': -1}, {'pid': True}, {'pid': '42'}, {'pid': [42]}, {'pid': 2 ** 32}, {'currency': 'doge'}, {'max_scan_bytes': 0}, {'max_scan_bytes': 268435457}, {'max_results': 0}, {'max_results': 10001}, {'max_results': True}]:
            with self.subTest(config=config):
                with self.assertRaises((ValueError, exceptions.PluginRequirementException)):
                    make_plugin(self, b'plain memory', **config)

    def test_json_renderer_outputs_exact_offsets_and_artifacts(self):
        data = b'padding ' + BTC + b' ' + ETH + b' end'
        plugin = make_plugin(self, data)
        rows = render(plugin)
        assert [row['Offset'] for row in rows] == [8, 8 + len(BTC) + 1]
        assert [row['Value'] for row in rows] == [BTC.decode(), ETH.decode()]
        assert all((row['PID'] == 42 and row['Process'] == 'synthetic.exe' for row in rows))
        assert findings()[0]['offset'] == 8
        result = summary()
        assert result['completion_state'] == 'complete'
        assert result['bytes_read'] == result['bytes_evaluated'] == len(data)
        assert result['findings'] == 2
        assert set(CaptureFile.outputs) == {'cryptomem-findings.jsonl', 'cryptomem-scan-summary.json'}

    def test_no_artifacts_is_only_scoped_absence(self):
        plugin = make_plugin(self, b'ordinary synthetic memory with no supported addresses')
        assert render(plugin) == []
        assert summary()['completion_state'] == 'complete'
        assert 'Selected process VADs only' in summary()['scope']

    def test_currency_filter_and_invalid_checksum(self):
        data = BTC[:-1] + b'U ' + ETH + b' '
        plugin = make_plugin(self, data, currency='btc')
        rows = render(plugin)
        assert len(rows) == 1
        assert rows[0]['Validation'] == 'checksum_invalid'
        assert rows[0]['Currency'] == 'BTC'

    def test_split_chunk_candidates_have_single_exact_location(self):
        for encoding in ['ascii', 'utf-16le']:
            with self.subTest(encoding=encoding):
                for split in [1, 16, 33]:
                    with self.subTest(split=split):
                        token = BTC.decode().encode(encoding)
                        start = scanner.CryptoMem.CHUNK_BYTES - split
                        data = b' ' * start + token + b' ' * scanner.CryptoMem.CHUNK_BYTES
                        rows = render(make_plugin(self, data))
                        assert len(rows) == 1
                        assert rows[0]['Offset'] == start
                        assert rows[0]['ByteLength'] == len(token)
                        assert summary()['bytes_evaluated'] == len(data)

    def test_candidate_at_overlap_frontier_not_duplicated(self):
        start = scanner.CryptoMem.CHUNK_BYTES - scanner.formats.MAX_ARTIFACT_BYTES
        data = b' ' * start + BTC + b' ' * scanner.CryptoMem.CHUNK_BYTES
        rows = render(make_plugin(self, data))
        assert [row['Offset'] for row in rows] == [start]

    def test_context_survives_delayed_frontier_and_chunk_boundaries(self):
        frontier = scanner.CryptoMem.CHUNK_BYTES - scanner.formats.MAX_ARTIFACT_BYTES - 2
        for encoding in ('ascii', 'utf-16le'):
            for text in ('"recipient": "' + BTC.decode() + '"',
                         'bitcoin:' + BTC.decode() + '?amount=1&label=' + 'x' * 300):
                for start in (frontier - 4, scanner.CryptoMem.CHUNK_BYTES - 20):
                    with self.subTest(encoding=encoding, text=text[:20], start=start):
                        data = b' ' * start + text.encode(encoding) + b' ' * 70000
                        expected = list(scanner.formats.find_artifacts(data, {'BTC', 'ETH', 'XRP'}))
                        render(make_plugin(self, data))
                        actual = [
                            {key: value for key, value in record.items()
                             if key not in ('pid', 'process', 'layer')}
                            for record in findings()
                        ]
                        order = lambda record: (record['offset'], record['kind'], record['encoding'])
                        self.assertEqual(sorted(actual, key=order), sorted(expected, key=order))

    def test_longer_token_across_chunk_is_not_truncated_to_valid_address(self):
        start = scanner.CryptoMem.CHUNK_BYTES - len(ETH)
        data = b' ' * start + ETH + b'abcdef ' + b' ' * 5000
        rows = render(make_plugin(self, data))
        assert rows == []

    def test_never_joins_distinct_vads(self):
        for gap in [0, 100]:
            with self.subTest(gap=gap):
                left, right = (BTC[:16], BTC[16:])
                data = left + b' ' * gap + right
                ranges = [(0, len(left) - 1), (len(left) + gap, len(data) - 1)]
                assert render(make_plugin(self, data, ranges=ranges)) == []

    def test_unreadable_memory_fails_with_partial_findings(self):
        data = b' ' + BTC + b' ' * (2 * scanner.CryptoMem.CHUNK_BYTES)
        plugin = make_plugin(self, data, layer_class=FaultLayer)
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Unreadable'):
            render(plugin)
        assert findings()[0]['offset'] == 1
        assert summary()['completion_state'] == 'incomplete'
        assert summary()['gaps'] == [{'start': scanner.CryptoMem.CHUNK_BYTES, 'length': scanner.CryptoMem.CHUNK_BYTES, 'invalid_address': scanner.CryptoMem.CHUNK_BYTES}]

    def test_corrupted_short_reads_fail(self):
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Short memory read'):
            render(make_plugin(self, b' ' + BTC + b' ', layer_class=ShortLayer))
        assert summary()['completion_state'] == 'incomplete'

    def test_byte_limit_preserves_only_fully_looked_ahead_candidates(self):
        data = b' ' + BTC + b' ' * 10000
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'byte limit'):
            render(make_plugin(self, data, max_scan_bytes=8000))
        assert summary()['bytes_read'] == 8000
        assert summary()['bytes_evaluated'] == 8000 - scanner.formats.MAX_ARTIFACT_BYTES - 2
        assert summary()['completion_state'] == 'incomplete'
        assert len(findings()) == 1

    def test_result_limit_retains_findings_and_marks_incomplete(self):
        data = b' ' + BTC + b' ' + BTC + b' '
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Result limit'):
            render(make_plugin(self, data, max_results=1))
        assert len(findings()) == summary()['findings'] == 1
        assert summary()['completion_state'] == 'incomplete'

    def test_exact_result_limit_can_complete(self):
        rows = render(make_plugin(self, b' ' + BTC + b' ', max_results=1))
        assert len(rows) == 1
        assert summary()['completion_state'] == 'complete'

    def test_invalid_vad_scope(self):
        for ranges, reason in [([], 'no readable VAD scope'), ([(-1, 10)], 'Invalid VAD'), ([(10, 1)], 'Invalid VAD'), ([(0, 10), (5, 20)], 'Overlapping VAD'), ([(0, 2 ** 64)], 'Invalid VAD')]:
            with self.subTest(ranges=ranges, reason=reason):
                with self.assertRaisesRegex(scanner.ScanIncomplete, reason):
                    render(make_plugin(self, b' ' * 100, ranges=ranges))
                assert summary()['completion_state'] == 'incomplete'

    def test_missing_pid_is_incomplete(self):
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'was not found'):
            render(make_plugin(self, b'memory', pid=43))
        assert summary()['bytes_read'] == 0

    def test_vad_traversal_cap(self):
        plugin = make_plugin(self, b' ' * 100, ranges=[(0, 20), (21, 40)])
        self.patch(plugin, 'MAX_VADS', 1)
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'VAD traversal'):
            render(plugin)

    def test_process_traversal_cap_counts_nonmatching_processes(self):
        plugin = make_plugin(self, b'memory', pid=43)
        self.patch(plugin, 'MAX_PROCESSES', 1)
        self.patch(scanner.pslist.PsList, 'list_processes', classmethod(
            lambda *args: iter([FakeProcess([(0, 5)]), FakeProcess([(0, 5)])])
        ))
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Process traversal'):
            render(plugin)

    def test_dependency_failure_is_not_empty_success(self):
        plugin = make_plugin(self, b' ' + ETH + b' ')

        def dependency_failure(*args):
            raise ImportError('synthetic missing checksum dependency')
        self.patch(scanner.formats, 'find_artifacts', dependency_failure)
        with self.assertRaisesRegex(ImportError, 'missing checksum dependency'):
            render(plugin)
        assert summary()['completion_state'] == 'incomplete'

    def test_dependency_is_checked_before_empty_scan(self):
        plugin = make_plugin(self, b'no addresses')
        def dependency_failure(*args):
            raise ImportError('synthetic missing checksum dependency')
        self.patch(scanner.formats, 'check_dependencies', dependency_failure)
        with self.assertRaisesRegex(ImportError, 'missing checksum dependency'):
            render(plugin)
        self.assertEqual(summary()['bytes_read'], 0)
        self.assertEqual(summary()['completion_state'], 'incomplete')

    def test_generator_close_records_incomplete_partial_findings(self):
        plugin = make_plugin(self, b' ' + BTC + b' ' + BTC + b' ')
        generator = plugin._generator()
        next(generator)
        generator.close()
        self.assertEqual(summary()['completion_state'], 'incomplete')
        self.assertEqual(summary()['findings'], 1)
        self.assertEqual(len(findings()), 1)

    def test_cooperative_interruption_preserves_incomplete_summary(self):
        plugin = make_plugin(self, b' ' + BTC + b' ' * 10000)

        def cancelled(*args):
            raise RuntimeError('synthetic cancellation')
        plugin._progress_callback = cancelled
        with self.assertRaisesRegex(RuntimeError, 'synthetic cancellation'):
            render(plugin)
        assert summary()['completion_state'] == 'incomplete'
        assert len(findings()) == 1
if __name__ == '__main__':
    unittest.main()
