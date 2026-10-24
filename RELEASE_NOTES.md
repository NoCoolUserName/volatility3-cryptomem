# CryptoMem 0.3.0 (prerelease)

Adds Linux x86-64 process memory-image analysis via `linux.cryptomem.CryptoMem`.
Windows command and output schema are preserved. Both adapters share bounded
reads and BTC, Ethereum, XRP and Monero validators without new dependencies.

Linux uses process TGIDs, scans one leader's VMAs once, and rejects thread IDs,
kernel threads and missing process layers. Gaps, limits and failures are explicit
incomplete scans. Matching captured-kernel symbols must be provided locally;
other Linux architectures are unsupported until tested. An address occurrence
never establishes wallet ownership or activity.

Install the complete source `plugins` tree, including the shared Windows-namespaced
helpers. Existing Windows-only file copies must add `cryptomem_scan.py` when
upgrading. MCP adopts the release via its hash-pinned inventory; Workbench needs
a subsequent backend pin update/repackage, not a separate detector.

Validation is synthetic only; see VALIDATION.md. Real-memory Linux validation
remains outstanding. This prerelease does not claim kernel/distribution coverage.
