# CryptoMem

An independently maintained, offline cryptocurrency artifact scanner for
Volatility 3 by [NoCoolUserName](https://github.com/NoCoolUserName).
Inspired by CryptoScan's detection ideas, with a new bounded scanner, address
validation, process/virtual-address provenance, and explicit scan coverage.
No MCP, Workbench, AI service, wallet application, or blockchain API is required.

## Supported scope

- Windows Intel32/Intel64 process memory with matching local Volatility symbols.
- Bitcoin legacy Base58Check and native Bech32/Bech32m address candidates.
- Ethereum-style hexadecimal address candidates; ERC-55 checksum validation.
- XRP classic address candidates with alphabet, payload, and checksum checks.
- ASCII and UTF-16LE strings, including matches crossing read-chunk boundaries.
- A bounded subset of direct-address `bitcoin:` and `ethereum:` payment requests.

This is address-format detection, not a wallet-format support matrix. An address
in a browser, document, clipboard, or other process does not establish wallet
installation, ownership, control, balance, or a transaction. An Ethereum-style
address does not identify an EVM network. A payment request is not payment evidence.
Compatible address prefixes also are not independent proof of a blockchain.

## Install and run with ordinary Volatility

The tested target is **Python 3.12+ and Volatility 3 2.28.2**. Other Volatility
versions are unvalidated. Use a separate analyzer virtual environment:

```sh
git clone https://github.com/NoCoolUserName/volatility3-cryptomem.git
cd volatility3-cryptomem
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/vol -p "$PWD/plugins" -h
.venv/bin/vol --offline -p "$PWD/plugins" -f /evidence/windows.raw \
  -o /case/outputs/cryptomem -r json windows.cryptomem.CryptoMem \
  --pid 1234 --currency all --max-scan-bytes 67108864 --max-results 1000
```

Create the output directory before running. On Windows, use `.venv\Scripts\python`
and `.venv\Scripts\vol.exe`, and an absolute path to the `plugins` directory.
Use `windows.pslist.PsList` to select the PID from actual evidence. Matching
symbols must already be available when `--offline` is used. The plugin has no
network client; `--offline` also disables Volatility's symbol downloads.

When reusing an existing analyzer, install the pinned dependencies in that
analyzer and pass this repository's `plugins` directory to `-p`. Do not replace
Volatility source files or copy the repository into its core. A release source
archive works like a clone. JSON, text, and other standard Volatility renderers
use the same plugin.

| Option | Meaning |
| --- | --- |
| `--pid` | One required positive process ID. |
| `--currency` | `all` (default), `btc`, `eth`, or `xrp`. |
| `--max-scan-bytes` | Default 67,108,864; maximum 268,435,456 bytes. |
| `--max-results` | Default 1,000; maximum 10,000 findings. |

## Results and completeness

Each row includes PID, process name, layer, virtual offset, byte length, original
value, format-aware comparison value, encoding, artifact type, validation status,
reason, and bounded contextual fields. Checksum-valid means the string passes
the implemented format checks; it does not verify activity or ownership.
Checksum-invalid candidates remain distinguishable from unchecked formats.
Amounts in payment requests remain strings; they are requested values, not
balances or observed transfers. Unsupported URI features are explicitly labeled.

The plugin saves `cryptomem-findings.jsonl` as findings are emitted and a
`cryptomem-scan-summary.json` coverage artifact through Volatility's output handler.
Ordinary renderer output is separate. Limits, unreadable memory, missing process
layers, or other scan failures do not become complete empty successes. Review
the command exit status and summary together. An interrupted run may have only
partial artifacts; missing final coverage is not completion.

Scanning is limited to the selected process's enumerated VAD ranges. Missing,
paged-out, compressed, encrypted, binary, or unenumerated content may contain
artifacts this scanner cannot recover. Read overlap is not carried across VAD
boundaries or missing memory. Repeated occurrences preserve distinct offsets;
repetition is not independent corroboration. No memory timestamps are invented.

## MCP and Workbench

[volatility-mcp](https://github.com/NoCoolUserName/volatility-mcp) installs a
hash-pinned source revision through its optional addon profile, then exposes
`windows.cryptomem.CryptoMem` through its existing `list_plugins` and `run_plugin`
tools. That integration adds process timeouts/cancellation, image hashes, case
confinement, artifact hashes, and saved-result reuse. These controls belong to
MCP; direct Volatility users manage host execution limits and acquisition hashes.
Workbench consumes the same core integration; it has no separate detector.

## Validation and limitations

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Tests use public format vectors, generated byte buffers, real Volatility layers
and renderers, and simulated process/VAD objects. See [VALIDATION.md](VALIDATION.md)
for the measured scope. **No real-memory recovery accuracy is claimed.**

This version does not extract private keys or mnemonic phrases, parse wallet
databases, reconstruct transactions, look up balances, resolve ENS names, or
follow URLs. CryptoScan's swap/transaction-hash and mnemonic heuristics are not
claimed as supported recovery features. New detectors require positive, negative,
malformed, encoding, and boundary fixtures plus explicit capability documentation.

## Attribution and license

Distributed under the [Volatility Software License 1.0](LICENSE), with retained
notices for any separately attributed standards material. Complete corresponding
source is published here. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for CryptoScan and format
references. This is an independent project, not an official CryptoScan release
or a project endorsed by the Volatility Foundation.
