"""Experimental offline address scanning in legacy Intel64 macOS captures."""
from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.mac import pslist
from volatility3.plugins.windows import cryptomem_scan as scan
from volatility3.plugins.windows.cryptomem_scan import ScanIncomplete


class CryptoMem(interfaces.plugins.PluginInterface):
    """Find address candidates in one Intel Mac process, without ownership inference."""

    _required_framework_version = (2, 28, 0)
    _version = (0, 4, 0)
    CHUNK_BYTES = 65536
    MAX_SCAN_BYTES = 268435456
    MAX_RESULTS = 10000
    MAX_PROCESSES = 65536
    MAX_VMAS = 65536

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Legacy Intel64 macOS kernel with matching local symbols",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0),
            ),
        ] + scan.parameter_requirements("One positive macOS BSD process ID (not a Mach thread ID)")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        scan.validate_parameters(self)

    def _process(self):
        # The tasks queue yields BSD proc objects via task.bsd_info, not threads.
        # Stop after selecting one proc; duplicated tasks never rescan its memory.
        for index, proc in enumerate(pslist.PsList.list_tasks_tasks(
            self.context, self.config["kernel"]
        )):
            if index >= self.MAX_PROCESSES:
                raise ScanIncomplete("Process traversal limit reached")
            if int(proc.p_pid) == self.config["pid"]:
                task = proc.get_task()
                if not task or not task.map:
                    raise ScanIncomplete("Selected process has no user address space")
                return proc
        raise ScanIncomplete(f"BSD process ID {self.config['pid']} was not found; Mach thread IDs are not accepted")

    @staticmethod
    def _process_name(proc):
        return utility.array_to_string(proc.p_comm, errors="replace")

    def _ranges(self, proc):
        expected = int(proc.get_task().map.hdr.nentries)
        if not 1 <= expected <= self.MAX_VMAS:
            raise ScanIncomplete("Invalid or excessive VM map entry count")
        ranges = []
        # get_map_iter silently stops on unreadable, repeated or poisoned entries.
        # Verify its count so damaged lists cannot masquerade as complete scopes.
        for index, entry in enumerate(proc.get_map_iter()):
            if index >= self.MAX_VMAS:
                raise ScanIncomplete("VM map traversal limit reached")
            if int(entry.is_sub_map):
                raise ScanIncomplete("Nested VM submaps are unsupported; scan cannot establish complete coverage")
            start, end = int(entry.links.start), int(entry.links.end)
            if not 0 <= start < end <= 2**64:
                raise ScanIncomplete("Invalid VM map address range")
            ranges.append((start, end))
        if len(ranges) != expected:
            raise ScanIncomplete("VM map enumeration is incomplete or inconsistent with its declared entry count")
        ranges.sort()
        if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
            raise ScanIncomplete("Overlapping VM map ranges prevent reliable coverage")
        return ranges

    def _generator(self):
        yield from scan.generate(self, "mac.cryptomem.CryptoMem", "VMA")

    def run(self):
        return scan.run(self)
