"""Offline, bounded cryptocurrency artifact scanning for Windows process memory.

CryptoMem is an independently maintained plugin informed by CryptoScan's scope.
Its implementation is not copied from CryptoScan. See the repository notices.
"""

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import cryptomem_formats as formats
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import cryptomem_scan as scan
from volatility3.plugins.windows.cryptomem_scan import ScanIncomplete


class CryptoMem(interfaces.plugins.PluginInterface):
    """Find candidate addresses and payment requests in one Windows process.

    Address validation establishes format/checksum validity only, never wallet
    ownership, control, a transaction, or the presence of wallet software.
    """

    _required_framework_version = (2, 28, 0)
    _version = (0, 3, 0)
    CHUNK_BYTES = 65536
    MAX_SCAN_BYTES = 268435456
    MAX_RESULTS = 10000
    MAX_PROCESSES = 65536
    MAX_VADS = 65536

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0),
            ),
        ] + scan.parameter_requirements("One positive Windows process ID")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        scan.validate_parameters(self)

    def _process(self):
        # Enumerate without a filter so the traversal cap applies to nonmatching
        # processes too. PsList's current API takes a kernel module name.
        for index, proc in enumerate(pslist.PsList.list_processes(
            self.context, self.config["kernel"]
        )):
            if index >= self.MAX_PROCESSES:
                raise ScanIncomplete("Process traversal limit reached")
            if int(proc.UniqueProcessId) == self.config["pid"]:
                return proc
        raise ScanIncomplete(f"PID {self.config['pid']} was not found")

    def _ranges(self, proc):
        ranges = []
        for index, vad in enumerate(proc.get_vad_root().traverse()):
            if index >= self.MAX_VADS:
                raise ScanIncomplete("VAD traversal limit reached")
            start, end = int(vad.get_start()), int(vad.get_end())
            if not 0 <= start <= end < 2**64:
                raise ScanIncomplete("Invalid VAD address range")
            ranges.append((start, end + 1))
        ranges.sort()
        if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
            raise ScanIncomplete("Overlapping VAD ranges prevent reliable coverage")
        if not ranges:
            raise ScanIncomplete("The selected process has no readable VAD scope")
        return ranges

    @staticmethod
    def _process_name(proc):
        return str(proc.ImageFileName.cast(
            "string", max_length=proc.ImageFileName.vol.count, errors="replace"
        ))

    def _generator(self):
        yield from scan.generate(self, "windows.cryptomem.CryptoMem", "VAD")

    def run(self):
        return scan.run(self)
