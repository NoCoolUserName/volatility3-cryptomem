"""Offline cryptocurrency artifacts in Linux x86-64 process memory."""
from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.plugins.windows import cryptomem_scan as scan
from volatility3.plugins.windows.cryptomem_scan import ScanIncomplete


class CryptoMem(interfaces.plugins.PluginInterface):
    """Find address candidates in one Linux process, without ownership inference."""

    _required_framework_version = (2, 28, 0)
    _version = (0, 5, 0)
    CHUNK_BYTES = 65536
    MAX_SCAN_BYTES = 268435456
    MAX_RESULTS = 10000
    MAX_PROCESSES = 65536
    MAX_VMAS = 65536

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel with matching local symbols",
                architectures=["Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 1, 1),
            ),
        ] + scan.parameter_requirements("One positive Linux process ID (TGID, not thread ID)")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        scan.validate_parameters(self)

    def _process(self):
        # No filter: nonmatching tasks also count toward the traversal limit.
        # tgid is the userspace process ID; pid is a task/thread ID. Only select
        # a group leader even if an enumerator happens to return user threads.
        for index, task in enumerate(pslist.PsList.list_tasks(
            self.context, self.config["kernel"], include_threads=False
        )):
            if index >= self.MAX_PROCESSES:
                raise ScanIncomplete("Process traversal limit reached")
            if int(task.tgid) != self.config["pid"] or int(task.pid) != int(task.tgid):
                continue
            if task.is_kernel_thread or not task.mm:
                raise ScanIncomplete("Selected task has no user address space (kernel thread or exiting task)")
            return task
        raise ScanIncomplete(f"Process ID (TGID) {self.config['pid']} was not found; thread IDs are not accepted")

    @staticmethod
    def _process_name(task):
        return utility.array_to_string(task.comm, errors="replace")

    def _ranges(self, task):
        ranges = []
        # Public Volatility API handles mmap lists and maple trees. vm_end is
        # exclusive, unlike the inclusive Windows VAD end.
        for index, vma in enumerate(task.mm.get_vma_iter()):
            if index >= self.MAX_VMAS:
                raise ScanIncomplete("VMA traversal limit reached")
            start, end = int(vma.vm_start), int(vma.vm_end)
            if not 0 <= start < end <= 2**64:
                raise ScanIncomplete("Invalid VMA address range")
            ranges.append((start, end))
        ranges.sort()
        if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
            raise ScanIncomplete("Overlapping VMA ranges prevent reliable coverage")
        if not ranges:
            raise ScanIncomplete("The selected process has no readable VMA scope")
        return ranges

    def _generator(self):
        yield from scan.generate(self, "linux.cryptomem.CryptoMem", "VMA")

    def run(self):
        return scan.run(self)
