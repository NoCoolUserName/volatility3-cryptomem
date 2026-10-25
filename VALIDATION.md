# Experimental Intel64 macOS adapter validation — 0.4.0

Target: Python 3.12.13, Volatility 3 2.28.2, PyCryptodome 3.23.0, ARM64 macOS host.
The 88-test standalone suite passes: 12 new Mac tests plus Windows, Linux and
format regressions. Actual CLI discovery preserves all native plugins and exposes
all three CryptoMem commands; each fails explicitly on a corrupt synthetic image.
Synthetic Mac fixtures exercise actual Volatility layers, requirements, renderers,
shared scanning and output handlers. BSD process enumeration and VM maps are
simulated, so this does not verify real Darwin page tables or kernel compatibility.

The Mac tests cover exact offsets/provenance/schema, all four currency families
across ASCII/UTF-16LE read boundaries, adjacent and separated mappings, unreadable
gaps, empty results, exclusive map ends, duplicate process objects, missing PIDs,
missing task/map/layer, invalid inputs, corrupt/overlapping maps, byte/result/
traversal limits, symbol errors, short reads and cooperative interruption.
Declared map counts detect silent truncation. Nested submaps are rejected before
scanning, explicitly including the limitation for shared-region submaps in ordinary
processes. Apple silicon, Intel32 and modern macOS are unsupported.

Volatility's installed Mac PsList 3.0.0, proc extension and map iterator APIs were
inspected before editing. The bundled public mac.zip has 129 tables; one Intel64
10.10.5 build14F1912 table was inspected for required proc/map fields. This is
symbol-schema inspection, not memory-image validation or a tested OS matrix.

**Real-memory macOS validation remains outstanding.** The upstream tutorial links
an older CTF acquisition, but a suitably licensed, verified image/symbol pair has
not been established here. No evidence was uploaded and no recovered code run.
A future validation must include a consented Intel64 image, exact symbols, known
positive/negative process buffers, independent offset checks and incomplete scans.

---

# Linux adapter validation — 0.3.0

Local target: Python 3.12.13, Volatility 3 2.28.2, PyCryptodome 3.23.0,
pefile 2024.8.26, macOS ARM64 analysis host. Linux guest scope is x86-64 only;
Intel32, ARM and other Linux architectures are unsupported until tested.

The 76-test standalone suite passes, including the existing Windows/format/Monero
regressions and 11 Linux tests. Synthetic byte buffers use real Volatility layers,
requirements, discovery and JSON rendering; task/VMA enumeration and the comm array
wrapper are simulated. Discovery retains native Linux and Windows catalogs. Both
actual CLI commands reject a corrupt synthetic image with unsatisfied requirements
and unchanged input. Symbol-error injection verifies explicit incomplete coverage.
Tests cover all four currencies across ASCII/UTF-16LE read boundaries, exact virtual
offsets, exclusive VMA ends, separated/adjacent mappings, unreadable gaps, partial
artifacts, empty results, invalid arguments, task/mapping/byte/result limits,
TGID/TID semantics, kernel threads, missing layers and interruption.

The inspected APIs are from the installed pinned Volatility source:
`linux.pslist.PsList.list_tasks` (4.1.1), `task_struct.add_process_layer`,
`task_struct.is_kernel_thread` and `mm_struct.get_vma_iter`. The latter dispatches
between mmap and maple-tree traversal and may skip invalid entries. Synthetic
adapters do not validate either traversal against an acquired kernel.

Real-memory Linux validation remains outstanding. The Volatility Foundation
[public sample index](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
and [Linux tutorial](https://volatility3.readthedocs.io/en/stable/getting-started-linux-tutorial.html)
were inspected on 2026-10-24; no suitable Linux x86-64 acquisition with verified
licensing and matching symbols was established for this run. No sample was
uploaded, recovered endpoint contacted, or recovered code executed. Future checks
need authorized positive/negative acquisitions, matching kernel ISFs, known address
locations and per-run coverage. Public availability alone is not a license check.
MCP timeout/cancellation and installed-profile checks belong to volatility-mcp's
integration validation; standalone tests do not substitute for those checks.

---

# Validation scope

CryptoMem currently has **synthetic and format-vector validation**, not validated
recovery accuracy on complete Windows memory acquisitions. Passing these tests
does not establish support for a particular wallet product or its storage format.

Run the suite in a fresh analyzer environment with the pinned dependencies:

```sh
python -m pip install -r requirements.txt
python -m pip check
python -m unittest discover -s tests -v
```

Use a fresh environment for discovery comparisons: a previously installed copy
of CryptoMem would already appear in the baseline plugin inventory.

## Automated checks

| Tests | What is exercised |
| --- | --- |
| `tests/test_formats.py` | Published Bitcoin witness-address and ERC-55 examples, Bitcoin/XRP Base58Check fixtures, payload/version/checksum failures, conservative uniform-case Ethereum classification, currency filters, ASCII/UTF-16LE offsets, repeated occurrences, token boundaries, bounded payment-request parsing, malformed/unsupported fields, missing dependencies, and offline behavior. |
| `tests/test_scanner.py` | Real Volatility `Context`, `BufferDataLayer`, requirements, `TreeGrid`, and JSON renderer with simulated processes and VADs. Checks include parameter validation, exact locations, chunk overlap and context, adjacent/separate VADs, strict unreadable/short reads, missing PID, malformed/overlapping ranges, traversal/byte/result caps, dependency failures, partial artifacts, and cooperative interruption. |
| `tests/test_discovery.py` | Separate real Volatility CLI processes: external plugin discovery preserves the native catalog, plugin help exposes the expected parameters, and a deliberately invalid synthetic acquisition fails without changing its input bytes. |
| `tests/test_monero.py` | Monero documentation examples and generated payloads for all nine network/type combinations, zero-padded blocks, block overflow, wrong lengths/prefixes, checksum corruption, SHA3-vs-Keccak, filtering, missing dependencies, ASCII/UTF-16LE locations, and real renderer/coverage artifacts across read boundaries. |

The scanner tests use an in-memory implementation of Volatility's file-handler
interface to inspect JSONL findings and coverage summaries. They exercise the
actual renderer and detector; `_EPROCESS` objects, VAD traversal, and process-layer
creation are simulated. They do not validate kernel discovery, symbol matching,
Windows page-table translation, or recovery from a real acquisition.

Incomplete scans must fail rather than resemble complete empty results. Tests
check retained partial findings and incomplete summaries for read failures and
limits. Cooperative callback interruption and generator closure are tested;
forced process termination cannot guarantee a final summary write. Host-level
timeouts, cancellation, case confinement, evidence hashes, and caching belong to
the separate [Volatility MCP integration](https://github.com/NoCoolUserName/volatility-mcp).

## Host and dependency checks

Local scanner validation used Python 3.12 with Volatility 3 2.28.2 and the pinned
requirements on macOS. CI is configured to run the suite on Ubuntu and Windows
with Python 3.12 and 3.13; consult the completed workflow for the tested revision.
Host operating systems are distinct from the supported Windows memory-image
scope.

A wheel-only dependency resolution for Windows x64/CPython 3.13 succeeded with
the pinned requirements. Volatility and pefile provide platform-independent
wheels; PyCryptodome provides a compatible Windows ABI3 wheel. This verifies
package availability, not execution on Windows. The tests use standard-library
`unittest`; pytest is not required. Keccak dependency initialization precedes the
scanner's subprocess guard because PyCryptodome can invoke the trusted platform
`file` utility while loading its native library on macOS.

## Required real-memory follow-up

Before making real-memory accuracy or wallet-product support claims:

1. Acquire consented, reproducible Windows Intel32 and Intel64 lab images with
   known addresses/payment requests in selected processes and matching local
   symbols. Record acquisition hashes, versions, actions, PIDs, and expected
   content. Keep acquisitions and any sensitive outputs outside Git.
2. Include a wallet process, a browser displaying the same address, and ordinary
   document/application controls. Add negative controls without supported
   artifacts. An address in a browser must remain address evidence, never proof
   of wallet ownership or control.
3. Verify reported process identity, layer, virtual offsets, encoding, and bytes
   independently against Volatility process/VAD inspection. Compare detected and
   expected occurrences, documenting missed artifacts and false positives.
4. Exercise paged-out or unreadable memory, constrained scan/result budgets, and
   interruptions. Check exit status, retained artifacts, and coverage together;
   a missing summary or incomplete scan must not support an absence claim.
5. Record runtime and resource use on representative process sizes. Publish only
   findings supported by that corpus, separating address-format validation from
   wallet behavior and limitations from acquisition quality.

No live blockchain query, recovered-code execution, evidence upload, or private
key/seed recovery is needed for this validation.
