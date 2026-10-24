"""Synthetic Linux tasks/VMAs, real Volatility layers and JSON renderer.

These buffers are not acquired RAM and do not validate any captured kernel.
"""
import importlib
import inspect
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.plugins import linux
from test_scanner import CaptureFile, render, summary, findings, FaultLayer, ShortLayer, BTC
import test_scanner as windows_fixture
from test_formats import ETH, XRP
from test_monero import STANDARD

linux.__path__.insert(0, str(Path(__file__).parents[1] / 'plugins/linux'))
scanner = importlib.import_module('volatility3.plugins.linux.cryptomem')


class Task:
    def __init__(self, ranges, pid=42, tgid=42, kernel=False, layer='process'):
        self.pid, self.tgid, self.is_kernel_thread = pid, tgid, kernel
        self.comm, self.layer = 'synthetic-linux', layer
        self.mm = SimpleNamespace(get_vma_iter=lambda: (
            SimpleNamespace(vm_start=start, vm_end=end) for start, end in ranges))
        self.add_process_layer = mock.Mock(return_value=layer)


def make_plugin(test, data, ranges=None, layer_class=BufferDataLayer, tasks=None, **config):
    context = contexts.Context()
    context.layers.add_layer(layer_class(context, 'layers.process', 'process', data))
    module = context.module('synthetic', 'process', 0)
    context.config['plugins.test.kernel'] = module.name
    context.config['plugins.test.pid'] = 42
    for name, value in config.items():
        if value is None:
            del context.config[f'plugins.test.{name}']
        else:
            context.config[f'plugins.test.{name}'] = value
    tasks = [Task(ranges if ranges is not None else [(0, len(data))])] if tasks is None else tasks

    def enumerate_tasks(ctx, kernel, *, include_threads):
        assert ctx is context and kernel == module.name
        assert include_threads is False
        return iter(tasks)

    test.patch(scanner.pslist.PsList, 'list_tasks', enumerate_tasks)
    # Only the Volatility array wrapper is simulated; no scanning is mocked.
    test.patch(scanner.utility, 'array_to_string', lambda value, **kwargs: value)
    plugin = scanner.CryptoMem(context, 'plugins.test')
    CaptureFile.outputs = {}
    plugin.set_open_method(CaptureFile)
    return plugin


class LinuxTests(unittest.TestCase):
    patch = windows_fixture.ScannerTests.patch
    setUp = windows_fixture.ScannerTests.setUp

    def test_api_architecture_and_schema(self):
        reqs = {req.name: req for req in scanner.CryptoMem.get_requirements()}
        self.assertEqual(reqs['kernel'].requirements['layer_name'].architectures, ['Intel64'])
        self.assertIn('vmlinux_module_name', inspect.signature(scanner.pslist.PsList.list_tasks).parameters)
        plugin = make_plugin(self, b' ' + BTC + b' ')
        row, = render(plugin)
        self.assertEqual(set(row) - {'__children'}, {'PID', 'Process', 'Layer', 'Offset', 'ByteLength',
            'Kind', 'Currency', 'Value', 'Canonical', 'Format', 'Validation', 'Reason',
            'Encoding', 'Context', 'Network', 'Amount'})
        self.assertEqual((row['PID'], row['Process'], row['Layer'], row['Offset']),
                         (42, 'synthetic-linux', 'process', 1))
        self.assertEqual(findings()[0]['offset'], 1)
        self.assertEqual(summary()['plugin'], 'linux.cryptomem.CryptoMem')
        self.assertEqual(summary()['vma_count'], summary()['completed_vmas'])

    def test_all_families_split_at_read_boundaries(self):
        for address in (BTC.decode(), ETH, XRP, STANDARD):
            for encoding in ('ascii', 'utf-16le'):
                token = address.encode(encoding)
                for split in (1, len(token)//2, len(token)-1):
                    with self.subTest(address=address[:8], encoding=encoding, split=split):
                        start = scanner.CryptoMem.CHUNK_BYTES - split
                        data = b' ' * start + token + b' ' * 70000
                        row, = render(make_plugin(self, data))
                        self.assertEqual((row['Value'], row['Offset'], row['ByteLength']),
                                         (address, start, len(token)))
                        self.assertEqual(row['Validation'], 'checksum_valid')
                        self.assertEqual(summary()['bytes_evaluated'], len(data))

    def test_never_joins_adjacent_or_separate_vmas(self):
        for gap in (0, 100):
            data = BTC[:16] + b' ' * gap + BTC[16:]
            self.assertEqual(render(make_plugin(self, data, ranges=[(0,16),(16+gap,len(data))])), [])
            self.assertEqual(summary()['completed_vmas'], 2)

    def test_unreadable_gap_never_fabricates_candidate(self):
        size = scanner.CryptoMem.CHUNK_BYTES
        data = b' ' * (size-16) + BTC[:16] + b' ' * size + BTC[16:]
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Unreadable'):
            render(make_plugin(self, data, layer_class=FaultLayer))
        self.assertEqual(findings(), [])
        self.assertEqual(summary()['completion_state'], 'incomplete')
        self.assertEqual(summary()['gaps'][0]['start'], size)

    def test_empty_and_exclusive_vma_end(self):
        data = b'plain ' + BTC + b' '
        self.assertEqual(render(make_plugin(self, data, ranges=[(0,6)])), [])
        self.assertEqual(summary()['bytes_read'], 6)
        self.assertEqual(summary()['completion_state'], 'complete')
        row, = render(make_plugin(self, data, ranges=[(6,6+len(BTC))]))
        self.assertEqual(row['Offset'], 6)

    def test_tgid_selects_one_leader_not_thread_ids(self):
        data = b' ' + BTC + b' '
        thread, leader = Task([(0,len(data))], pid=43), Task([(0,len(data))])
        row, = render(make_plugin(self, data, tasks=[thread, leader, leader]))
        self.assertEqual(row['PID'], 42)
        thread.add_process_layer.assert_not_called()
        leader.add_process_layer.assert_called_once()
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'thread IDs'):
            render(make_plugin(self, data, tasks=[thread,leader], pid=43))

    def test_missing_pid_kernel_threads_and_unusable_layer_fail(self):
        for task in (Task([(0,8)], kernel=True), Task([(0,8)], layer=None)):
            with self.assertRaises(scanner.ScanIncomplete):
                render(make_plugin(self, b'ordinary', tasks=[task]))
            self.assertEqual(summary()['completion_state'], 'incomplete')
        task = Task([(0,8)]); task.mm = None
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'no user address space'):
            render(make_plugin(self, b'ordinary', tasks=[task]))
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'not found'):
            render(make_plugin(self, b'ordinary', tasks=[]))

    def test_invalid_inputs_and_mapping_ranges(self):
        for config in ({'pid':0}, {'pid':-1}, {'pid':True}, {'pid':None}, {'pid':2**32},
                       {'currency':'doge'}, {'max_scan_bytes':0}, {'max_scan_bytes':268435457},
                       {'max_results':0}, {'max_results':10001}):
            with self.subTest(config=config), self.assertRaises((ValueError, exceptions.PluginRequirementException)):
                make_plugin(self, b'plain', **config)
        for ranges in ([], [(-1,4)], [(5,5)], [(6,5)], [(0,2**64+1)], [(0,5),(4,8)]):
            with self.subTest(ranges=ranges), self.assertRaises(scanner.ScanIncomplete):
                render(make_plugin(self, b'plain memory', ranges=ranges))
            self.assertEqual(summary()['completion_state'], 'incomplete')

    def test_limits_fail_with_partial_artifacts(self):
        data = b' ' + BTC + b' ' + BTC + b' ' * 10000
        for config, reason in (({'max_scan_bytes':8000}, 'byte limit'), ({'max_results':1}, 'Result limit')):
            with self.subTest(config=config), self.assertRaisesRegex(scanner.ScanIncomplete, reason):
                render(make_plugin(self, data, **config))
            self.assertTrue(findings())
            self.assertEqual(summary()['completion_state'], 'incomplete')
        plugin = make_plugin(self, data, ranges=[(0,10),(10,20)])
        plugin.MAX_VMAS = 1
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'VMA traversal'):
            render(plugin)
        plugin = make_plugin(self, data, tasks=[Task([(0,10)],pid=41,tgid=41),Task([(0,10)])])
        plugin.MAX_PROCESSES = 1
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Process traversal'):
            render(plugin)

    def test_missing_symbols_enumeration_failure_and_short_reads(self):
        plugin = make_plugin(self, b'plain memory')
        self.patch(scanner.pslist.PsList, 'list_tasks', mock.Mock(side_effect=exceptions.SymbolError('init_task','synthetic')))
        with self.assertRaises(exceptions.SymbolError):
            render(plugin)
        self.assertEqual(summary()['bytes_read'], 0)
        self.assertIn('SymbolError', summary()['reason'])
        task = Task([(0,12)])
        task.mm.get_vma_iter = mock.Mock(side_effect=AttributeError('Unable to find mmap or mm_mt'))
        with self.assertRaisesRegex(AttributeError, 'mmap or mm_mt'):
            render(make_plugin(self, b'plain memory', tasks=[task]))
        with self.assertRaisesRegex(scanner.ScanIncomplete, 'Short memory read'):
            render(make_plugin(self, b' ' + BTC + b' ', layer_class=ShortLayer))

    def test_interruption_preserves_incomplete_summary(self):
        plugin = make_plugin(self, b' ' + BTC + b' ' + BTC + b' ')
        generator = plugin._generator()
        next(generator)
        generator.close()
        self.assertEqual(summary()['completion_state'], 'incomplete')
        self.assertEqual(len(findings()), 1)


if __name__ == '__main__':
    unittest.main()
