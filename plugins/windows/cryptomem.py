"""Offline, bounded cryptocurrency artifact scanning for Windows process memory.

CryptoMem is an independently maintained plugin informed by CryptoScan's scope.
Its implementation is not copied from CryptoScan. See the repository notices.
"""

import json

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import cryptomem_formats as formats
from volatility3.plugins.windows import pslist


class ScanIncomplete(RuntimeError):
    """Some requested memory could not be examined completely."""


class CryptoMem(interfaces.plugins.PluginInterface):
    """Find candidate addresses and payment requests in one Windows process.

    Address validation establishes format/checksum validity only, never wallet
    ownership, control, a transaction, or the presence of wallet software.
    """

    _required_framework_version = (2, 28, 0)
    _version = (0, 2, 0)
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
            requirements.IntRequirement(
                name="pid", description="One positive Windows process ID",
                optional=False,
            ),
            requirements.ChoiceRequirement(
                name="currency", description="Address families to scan",
                choices=["all", "btc", "eth", "xrp", "xmr"], default="all", optional=True,
            ),
            requirements.IntRequirement(
                name="max_scan_bytes",
                description="Maximum process bytes to read (1..268435456)",
                default=67108864, optional=True,
            ),
            requirements.IntRequirement(
                name="max_results", description="Maximum findings (1..10000)",
                default=1000, optional=True,
            ),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, maximum in (("pid", 0xFFFFFFFF),
                              ("max_scan_bytes", self.MAX_SCAN_BYTES),
                              ("max_results", self.MAX_RESULTS)):
            value = self.config[name]
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer from 1 to {maximum}")
        if self.config["currency"] not in {"all", "btc", "eth", "xrp", "xmr"}:
            raise ValueError("currency must be one of: all, btc, eth, xrp, xmr")

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
    def _json_line(handler, record):
        handler.write((json.dumps(record, ensure_ascii=True) + "\n").encode("utf-8"))
        handler.flush()

    def _generator(self):
        summary = {
            "schema_version": 1,
            "plugin": "windows.cryptomem.CryptoMem",
            "plugin_version": ".".join(map(str, self._version)),
            "pid": self.config["pid"], "process": None, "layer": None,
            "currency": self.config["currency"],
            "max_scan_bytes": self.config["max_scan_bytes"],
            "max_results": self.config["max_results"],
            "scope": "Selected process VADs only; no ownership or activity inference",
            "bytes_scoped": 0, "bytes_read": 0, "bytes_evaluated": 0,
            "vad_count": 0, "completed_vads": 0, "findings": 0,
            "gaps": [], "completion_state": "incomplete", "reason": "Scan interrupted",
            "coverage_note": (
                "bytes_evaluated counts candidate-start locations with enough "
                "lookahead or a VAD end; unreadable chunks are not zero padded."
            ),
        }
        currencies = ({"BTC", "ETH", "XRP", "XMR"} if self.config["currency"] == "all"
                      else {self.config["currency"].upper()})
        try:
            formats.check_dependencies(currencies)
            proc = self._process()
            summary["process"] = str(proc.ImageFileName.cast(
                "string", max_length=proc.ImageFileName.vol.count, errors="replace"
            ))
            layer_name = proc.add_process_layer()
            summary["layer"] = layer_name
            layer = self.context.layers[layer_name]
            ranges = self._ranges(proc)
            summary["vad_count"] = len(ranges)
            summary["bytes_scoped"] = sum(end - start for start, end in ranges)
            with self.open("cryptomem-findings.jsonl") as findings_file:
                for start, end in ranges:
                    cursor, frontier, window_start, window = start, start, start, b""
                    while cursor < end:
                        remaining = self.config["max_scan_bytes"] - summary["bytes_read"]
                        if remaining <= 0:
                            raise ScanIncomplete("Scan byte limit reached; remaining VAD memory was not examined")
                        length = min(self.CHUNK_BYTES, end - cursor, remaining)
                        try:
                            block = layer.read(cursor, length, pad=False)
                        except exceptions.InvalidAddressException as exc:
                            summary["gaps"].append({
                                "start": cursor, "length": length,
                                "invalid_address": int(exc.invalid_address),
                            })
                            raise ScanIncomplete(
                                f"Unreadable process memory at {cursor:#x}; scan stopped"
                            ) from exc
                        if len(block) != length:
                            summary["gaps"].append({"start": cursor, "length": length})
                            raise ScanIncomplete(f"Short memory read at {cursor:#x}")
                        window += block
                        cursor += length
                        summary["bytes_read"] += length
                        # Defer starts near a chunk end. A candidate may need the
                        # maximum artifact length and a UTF-16 right boundary.
                        # Retain enough preceding data to preserve a containing
                        # URI and the helper's bounded direct-field context.
                        safe_end = cursor if cursor == end else max(
                            frontier, cursor - formats.MAX_ARTIFACT_BYTES - 2
                        )
                        for artifact in formats.find_artifacts(window, currencies):
                            offset = window_start + artifact["offset"]
                            if not frontier <= offset < safe_end:
                                continue
                            if summary["findings"] >= self.config["max_results"]:
                                raise ScanIncomplete("Result limit reached; additional findings exist")
                            record = {"pid": summary["pid"], "process": summary["process"],
                                      "layer": layer_name, **artifact, "offset": offset}
                            self._json_line(findings_file, record)
                            summary["findings"] += 1
                            yield (0, (
                                record["pid"], record["process"], record["layer"],
                                format_hints.Hex(record["offset"]), record["length"],
                                *[str(record[name]) for name in (
                                    "kind", "currency", "value", "canonical", "format",
                                    "validation", "reason", "encoding", "context", "network", "amount",
                                )],
                            ))
                        summary["bytes_evaluated"] += safe_end - frontier
                        frontier = safe_end
                        retain_start = max(
                            window_start, frontier - formats.MAX_ARTIFACT_BYTES - 128
                        )
                        window = window[retain_start - window_start:]
                        window_start = retain_start
                        self._progress_callback(
                            min(99.0, 100.0 * summary["bytes_read"] / summary["bytes_scoped"]),
                            "Scanning selected process VADs",
                        )
                    summary["completed_vads"] += 1
            self._progress_callback(100.0, "CryptoMem scan complete")
            summary["completion_state"] = "complete"
            summary["reason"] = "All selected VAD bytes examined"
        except Exception as exc:
            summary["completion_state"] = "incomplete"
            summary["reason"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            # Volatility's configured file handler owns all output locations.
            # A forcibly terminated process cannot guarantee this final write.
            with self.open("cryptomem-scan-summary.json") as summary_file:
                self._json_line(summary_file, summary)

    def run(self):
        return renderers.TreeGrid([
            ("PID", int), ("Process", str), ("Layer", str),
            ("Offset", format_hints.Hex), ("ByteLength", int),
            ("Kind", str), ("Currency", str), ("Value", str), ("Canonical", str),
            ("Format", str), ("Validation", str), ("Reason", str),
            ("Encoding", str), ("Context", str), ("Network", str), ("Amount", str),
        ], self._generator())
