# CryptoMem

An independently maintained, offline cryptocurrency artifact scanner for
Volatility 3 by [NoCoolUserName](https://github.com/NoCoolUserName).
Inspired by CryptoScan's detection ideas, with a new bounded scanner, address
validation, process/virtual-address provenance, and explicit scan coverage.
No MCP, Workbench, AI service, wallet application, or blockchain API is required.

## Supported scope

- Windows Intel32/Intel64 process memory with matching local Volatility symbols.
- Linux x86-64 (Intel64) process memory; other Linux architectures are unsupported
  until tested. This is memory-image analysis, not Linux desktop packaging.
- Experimental legacy macOS x86-64 (Intel64) process memory with exact matching
  Darwin kernel symbols. Intel32, Apple silicon/ARM64 and modern macOS builds are
  unsupported until separately implemented and validated.
- Bitcoin legacy Base58Check and native Bech32/Bech32m address candidates.
- Ethereum-style hexadecimal address candidates; ERC-55 checksum validation.
- XRP classic address candidates with alphabet, payload, and checksum checks.
- Monero standard addresses, subaddresses and integrated addresses: block Base58,
  type/length, mainnet/testnet/stagenet prefix and Keccak-256 checksum checks.
- ASCII and UTF-16LE strings, including matches crossing read-chunk boundaries.
- A bounded subset of direct-address `bitcoin:` and `ethereum:` payment requests.
- Opt-in English BIP-39 phrases (12/15/18/21/24 words), with entropy checksum.
- Opt-in Bitcoin WIF and BIP-32 xprv/tprv serialized private-key candidates.
- Opt-in hexadecimal transaction-ID candidates with confidence and ambiguity.

This is text-format detection, not a wallet-format support matrix. An address
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

For Linux, select the **PID/TGID** from `linux.pslist.PsList`, not its TID column:

```sh
.venv/bin/vol --offline -p "$PWD/plugins" -s /symbols/matching-kernel \
  -f /evidence/linux.lime -o /case/outputs/cryptomem -r json \
  linux.cryptomem.CryptoMem --pid 1234 --currency all
```

Linux symbols must match the **captured kernel build**, including its configuration
and architecture. A bundled symbol pack does not cover every distribution or
kernel. Provision a matching ISF before scanning offline; see Volatility's
[Linux symbols documentation](https://volatility3.readthedocs.io/en/stable/symbol-tables.html).
Unsatisfied kernel/layer/symbol requirements fail before a scan summary can be
created; retain CLI stderr and the nonzero exit status. That is not a negative finding.

For a legacy Intel64 macOS capture, select a BSD PID from `mac.pslist.PsList`:

```sh
.venv/bin/vol --offline -p "$PWD/plugins" -s /symbols/matching-darwin-kernel \
  -f /evidence/mac.raw -o /case/outputs/cryptomem -r json \
  mac.cryptomem.CryptoMem --pid 1234 --currency all
```

The existing Mac symbol pack can be reused **only when its Darwin kernel banner
matches the capture**; it is not universal Mac coverage. Volatility 3's macOS
analysis is [no longer actively maintained](https://volatility3.readthedocs.io/en/stable/getting-started-mac-tutorial.html).
CryptoMem's Mac adapter is experimental and synthetic-tested, not validated against
an acquired Mac image. Running the analyzer on an Apple-silicon host does not add
support for Apple-silicon captures. No memory acquisition capability is added.

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
| `--currency` | `all` (default), `btc`, `eth`, `xrp`, or `xmr`. |
| `--max-scan-bytes` | Default 67,108,864; maximum 268,435,456 bytes. |
| `--max-results` | Default 1,000; maximum 10,000 findings. |
| `--detect-mnemonics` | Opt in to checksum-valid English BIP-39 phrase candidates. |
| `--detect-private-keys` | Opt in to WIF and xprv/tprv candidates, including distinguishable validation failures. |
| `--detect-txids` | Opt in to ambiguous 64-hex candidates, optionally prefixed `0x`. |
| `--extract-secrets` | Explicitly save full detected secrets through a private POSIX output handler; requires a secret detector. |

All new flags default to false. `--currency` continues to select address families;
it does not select mnemonic/key/transaction detectors. The existing Windows,
Linux and Mac command names, defaults and renderer columns are preserved.

For example, add `--detect-mnemonics --detect-private-keys --detect-txids` to an
ordinary offline single-PID command. Values of mnemonic and recognizable key
candidates are masked in every renderer and ordinary artifact, even when invalid
or when they are public examples. No prefix, suffix or secret fingerprint is
returned. Sensitive payment-request messages are masked even in address-only mode.
See [EXTENDED_FORMATS.md](EXTENDED_FORMATS.md) for the versioned artifact contract,
supported normalization, extraction permissions and interpretation boundaries.

## Results and completeness

Each row includes PID, process name, layer, virtual offset, byte length, original
value, format-aware comparison value, encoding, artifact type, validation status,
reason, and bounded contextual fields. Checksum-valid means the string passes
the implemented format checks; it does not verify activity or ownership.
Checksum-invalid candidates remain distinguishable from unchecked formats.
Amounts in payment requests remain strings; they are requested values, not
balances or observed transfers. Unsupported URI features are explicitly labeled.

CryptoMem 0.2.0 includes Monero in `all`; use `--currency xmr` for Monero alone.
`Format` distinguishes `Monero-standard`, `Monero-subaddress` and
`Monero-integrated`. Prefix-derived network labels end in `-compatible` and do
not prove blockchain activity. Validation checks encoding and checksum, not
elliptic-curve public-key validity. It preserves the complete integrated address
without separately extracting its payment ID. Literal addresses inside `monero:`
text can be found, but Monero URI amounts/options are not interpreted. Seeds,
keys, wallet files, mining configuration and transaction hashes are outside the
Monero address detector's scope. Ethereum and Monero reuse the existing pinned PyCryptodome
dependency; no new runtime dependency is added.

The plugin saves `cryptomem-findings.jsonl` as findings are emitted and a
`cryptomem-scan-summary.json` coverage artifact through Volatility's output handler.
Ordinary renderer output is separate. Limits, unreadable memory, missing process
layers, or other scan failures do not become complete empty successes. Review
the command exit status and summary together. An interrupted run may have only
partial artifacts; missing final coverage is not completion.

CryptoMem 0.3.0 adds `linux.cryptomem.CryptoMem`. The Windows command, options,
row columns and summary keys remain unchanged. All adapters use the same bounded
scanner and address validators; the plain shared helpers remain under
`plugins/windows/cryptomem_scan.py` and `cryptomem_formats.py` to preserve the
existing installation layout. Install the entire `plugins` tree for every OS.
Linux summary keys use `vma_count` and `completed_vmas` instead of Windows VAD keys.

Linux selects one thread-group leader (`task.tgid == task.pid`) using
`PsList.list_tasks(..., include_threads=False)`, rejects TIDs and kernel threads
or exiting tasks without `mm`, and creates one process layer. VMAs come from
`mm.get_vma_iter()` (linked lists or maple trees); `vm_end` is exclusive.
Unreadable/short reads stop the scan, preserve prior findings, and mark coverage
incomplete. The scanner never pads or bridges a gap. Task and mapping enumeration
are capped at 65,536 yielded entries; upstream traversal can do additional work,
so use an external execution timeout. Volatility may omit invalid tasks/VMAs;
complete means only all **enumerated** mapping bytes, never all possible memory.

CryptoMem 0.4.0 adds `mac.cryptomem.CryptoMem`, using the existing Mac
`PsList.list_tasks_tasks()` API to select one BSD process, then its process layer
and `proc.get_map_iter()` entries. It does not enumerate or scan Mach threads.
PID zero/kernel_task is rejected. VM-map ends are exclusive; Mac summaries use
`vma_count` and `completed_vmas`. Declared entry counts must match enumeration.
Nested VM submaps are currently unsupported: a process containing one fails with
explicit incomplete coverage before scanning, rather than flattening separate
child mappings into a false contiguous match. Missing map fields, damaged lists,
missing layers, unreadable pages and limits also fail explicitly. This limitation
can affect ordinary processes that use shared-region submaps; symbols alone do
not resolve it. No supported macOS build matrix is claimed.

Scanning is limited to the selected process's enumerated Windows VAD or Linux/macOS VMA ranges. Missing,
paged-out, compressed, encrypted, binary, or unenumerated content may contain
artifacts this scanner cannot recover. Read overlap is not carried across mapping
boundaries or missing memory. Repeated occurrences preserve distinct offsets;
repetition is not independent corroboration. No memory timestamps are invented.

## MCP and Workbench

[volatility-mcp](https://github.com/NoCoolUserName/volatility-mcp) installs a
hash-pinned source revision through its optional addon profile, then exposes
`windows.cryptomem.CryptoMem`, `linux.cryptomem.CryptoMem` and
`mac.cryptomem.CryptoMem` through its existing `list_plugins` and `run_plugin`
tools. That integration adds process timeouts/cancellation, image hashes, case
confinement, artifact hashes, and saved-result reuse. These controls belong to
MCP; direct Volatility users manage host execution limits and acquisition hashes.
Workbench consumes the same core integration; it has no separate detector.

## Validation and limitations

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Tests use public format vectors, generated byte buffers, real Volatility layers
and renderers, and simulated process/VAD/VMA objects. See [VALIDATION.md](VALIDATION.md)
for the measured scope. **No real-memory recovery accuracy is claimed.**

This version does not parse wallet databases, recover encrypted wallets or
passphrases, reconstruct transactions, look up balances, resolve ENS names, follow
URLs, or perform wallet transactions. Other mnemonic languages/schemes, arbitrary
32-byte key searches, unrelated key formats (including BIP-38 and yprv/zprv), and
chain/confirmation/history attribution remain unsupported.

## Attribution and license

Distributed under the [Volatility Software License 1.0](LICENSE), with retained
notices for any separately attributed standards material. Complete corresponding
source is published here. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for CryptoScan and format
references. This is an independent project, not an official CryptoScan release
or a project endorsed by the Volatility Foundation.
