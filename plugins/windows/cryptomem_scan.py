"""Shared bounded scanner and output helpers; no plugin class or registry.

Kept alongside the original formats module for existing source installations.
Linux, macOS and Windows adapters supply process selection, names and mapping ranges.
"""
import json
import os
import stat
from contextlib import ExitStack
from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import cryptomem_formats as formats
from volatility3.plugins.windows import cryptomem_extended as extended


class ScanIncomplete(RuntimeError):
    """Some requested memory could not be examined completely."""


def _json_line(handler, record):
    handler.write((json.dumps(record, ensure_ascii=True) + "\n").encode("utf-8"))
    handler.flush()

def generate(self, command, region):
    richer = any(self.config.get(name, False) for name in (
        "detect_mnemonics", "detect_private_keys", "detect_txids"))
    suffix = "-v2" if richer else ""
    summary = {
        "schema_version": 1,
        "plugin": command,
        "plugin_version": ".".join(map(str, self._version)),
        "pid": self.config["pid"], "process": None, "layer": None,
        "currency": self.config["currency"],
        "max_scan_bytes": self.config["max_scan_bytes"],
        "max_results": self.config["max_results"],
        "scope": f"Selected process {region}s only; no ownership or activity inference",
        "bytes_scoped": 0, "bytes_read": 0, "bytes_evaluated": 0,
        f"{region.lower()}_count": 0, f"completed_{region.lower()}s": 0, "findings": 0,
        "gaps": [], "completion_state": "incomplete", "reason": "Scan interrupted",
        "coverage_note": (
            "bytes_evaluated counts candidate-start locations with enough "
            f"lookahead or a {region} end; unreadable chunks are not zero padded. "
            "Coverage is limited to enumerated mappings; upstream enumeration "
            "may omit invalid or unavailable entries."
        ),
    }
    currencies = ({"BTC", "ETH", "XRP", "XMR"} if self.config["currency"] == "all"
                  else {self.config["currency"].upper()})
    if richer:
        summary.update(schema_version=2,
                       detectors={name: self.config[name] for name in (
                           "detect_mnemonics", "detect_private_keys", "detect_txids")},
                       secrets_extracted=self.config["extract_secrets"],
                       secret_values="masked in ordinary outputs")
    try:
        if self.config.get("detect_mnemonics", False):
            extended.check_wordlist()
        formats.check_dependencies(currencies)
        proc = self._process()
        summary["process"] = extended.redact_text(self._process_name(proc))
        layer_name = proc.add_process_layer()
        if not layer_name:
            raise ScanIncomplete("The selected process has no usable process layer")
        summary["layer"] = extended.redact_text(layer_name)
        layer = self.context.layers[layer_name]
        ranges = self._ranges(proc)
        summary[f"{region.lower()}_count"] = len(ranges)
        summary["bytes_scoped"] = sum(end - start for start, end in ranges)
        # Use close callbacks: FileHandlerInterface.__exit__ logs exception text,
        # which can contain recovered bytes from a failing process layer.
        with ExitStack() as outputs:
            findings_file = self.open(f"cryptomem-findings{suffix}.jsonl")
            outputs.callback(findings_file.close)
            secrets_file = None
            if self.config.get("extract_secrets", False):
                secrets_file = self.open("cryptomem-secrets-v1.jsonl")
                outputs.callback(secrets_file.close)
                # Fail closed for in-memory/custom handlers without a private,
                # regular POSIX fd. Never bypass the configured output handler.
                fd = secrets_file.fileno()
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError("Secret extraction requires a regular private output file")
                os.fchmod(fd, 0o600)
                if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                    raise ValueError("Secret extraction could not establish private permissions")
            for start, end in ranges:
                cursor, frontier, window_start, window = start, start, start, b""
                while cursor < end:
                    remaining = self.config["max_scan_bytes"] - summary["bytes_read"]
                    if remaining <= 0:
                        raise ScanIncomplete(f"Scan byte limit reached; remaining {region} memory was not examined")
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
                    artifacts = formats.find_artifacts(window, currencies)
                    if richer:
                        artifacts = sorted([
                            *artifacts, *extended.find_artifacts(window,
                                mnemonics=self.config["detect_mnemonics"],
                                keys=self.config["detect_private_keys"],
                                txids=self.config["detect_txids"]),
                        ], key=lambda item: (item["offset"], item["kind"], item["encoding"]))
                    for artifact in artifacts:
                        offset = window_start + artifact["offset"]
                        if not frontier <= offset < safe_end:
                            continue
                        if summary["findings"] >= self.config["max_results"]:
                            raise ScanIncomplete("Result limit reached; additional findings exist")
                        record = {"pid": summary["pid"], "process": summary["process"],
                                  "layer": summary["layer"], **artifact, "offset": offset}
                        secret = record["kind"] in {"mnemonic", "private_key"}
                        if richer:
                            record.update(schema_version=2, secret=secret)
                            record.setdefault("confidence", "format_only")
                            record.setdefault("ambiguity", "Format occurrence does not establish ownership or activity")
                        if secret:
                            if secrets_file is not None:
                                _json_line(secrets_file, {**record, "schema_version": 1})
                            record = {**record, "value": extended.MASK, "canonical": extended.MASK}
                        else:
                            # A payment-request label/message can itself contain
                            # a recognizable secret, even in address-only mode.
                            record = {key: extended.redact_text(value) if isinstance(value, str) else value
                                      for key, value in record.items()}
                        _json_line(findings_file, record)
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
                        f"Scanning selected process {region}s",
                    )
                summary[f"completed_{region.lower()}s"] += 1
        self._progress_callback(100.0, "CryptoMem scan complete")
        summary["completion_state"] = "complete"
        summary["reason"] = f"All selected {region} bytes examined"
    except Exception as exc:
        summary["completion_state"] = "incomplete"
        summary["reason"] = f"{type(exc).__name__}: {extended.redact_text(str(exc))}"
        if richer:
            summary["reason"] = (f"ScanIncomplete: {extended.redact_text(str(exc))}" if isinstance(exc, ScanIncomplete)
                                 else f"{type(exc).__name__}: Extended scan failed; partial coverage only")
            raise ScanIncomplete(summary["reason"]) from None
        if extended.redact_text(str(exc)) != str(exc):
            raise ScanIncomplete(summary["reason"]) from None
        raise
    finally:
        # Volatility's configured file handler owns all output locations.
        # A forcibly terminated process cannot guarantee this final write.
        summary_file = self.open(f"cryptomem-scan-summary{suffix}.json")
        try:
            _json_line(summary_file, summary)
        finally:
            summary_file.close()

def run(self):
    return renderers.TreeGrid([
        ("PID", int), ("Process", str), ("Layer", str),
        ("Offset", format_hints.Hex), ("ByteLength", int),
        ("Kind", str), ("Currency", str), ("Value", str), ("Canonical", str),
        ("Format", str), ("Validation", str), ("Reason", str),
        ("Encoding", str), ("Context", str), ("Network", str), ("Amount", str),
    ], self._generator())


def parameter_requirements(pid_description):
    return [
        requirements.IntRequirement(
            name="pid", description=pid_description,
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
        *[requirements.BooleanRequirement(name=name, description=description,
                                          default=False, optional=True) for name, description in (
            ("detect_mnemonics", "Opt in to English BIP-39 checksum validation (masked)"),
            ("detect_private_keys", "Opt in to Bitcoin WIF and BIP-32 xprv/tprv validation (masked)"),
            ("detect_txids", "Opt in to ambiguous hexadecimal transaction-ID candidates"),
            ("extract_secrets", "Explicitly save full secrets in private configured case outputs (POSIX handler only)"),
        )],
    ]


def validate_parameters(self):
    for name, maximum in (("pid", 0xFFFFFFFF),
                          ("max_scan_bytes", self.MAX_SCAN_BYTES),
                          ("max_results", self.MAX_RESULTS)):
        value = self.config[name]
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer from 1 to {maximum}")
    if self.config["currency"] not in {"all", "btc", "eth", "xrp", "xmr"}:
        raise ValueError("currency must be one of: all, btc, eth, xrp, xmr")
    for name in ("detect_mnemonics", "detect_private_keys", "detect_txids", "extract_secrets"):
        if type(self.config[name]) is not bool:
            raise ValueError(f"{name} must be a boolean")
    if self.config["extract_secrets"]:
        if not (self.config["detect_mnemonics"] or self.config["detect_private_keys"]):
            raise ValueError("extract_secrets requires a secret detector")
        if os.name != "posix":
            raise ValueError("Secret extraction requires a POSIX private file handler")
