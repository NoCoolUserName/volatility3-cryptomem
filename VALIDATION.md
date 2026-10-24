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
