# CryptoMem 0.5.0 (prerelease)

Adds independently opt-in English BIP-39 checksum validation, Bitcoin WIF and
BIP-32 xprv/tprv validation, and explicitly ambiguous hexadecimal transaction-ID
candidates. Existing commands, currency/default address behavior and renderer
columns remain; richer findings use separate schema-2 files. Recognizable secret
values are masked across renderers, artifacts and failures. Only explicit
`--extract-secrets` writes full values via a regular private POSIX output handler.
The MCP integration must block full extraction from all output-reading routes.

The pinned English word list and public BIP-32 vector add no runtime dependency.
NFKD and source-span preservation cover supported wide English transcription.
WIF/extended formats, scalar/version/root checks, field hints, confidence and
boundaries are documented in EXTENDED_FORMATS.md. No encrypted-wallet recovery,
other mnemonic schemes/languages, arbitrary binary keys, transaction parsing,
network enrichment, balance/ownership inference or wallet transactions are added.

Synthetic buffers/public vectors only: Windows/Linux/legacy Intel64 Mac adapters,
ordinary read boundaries, mappings/gaps, limits, renderers and extraction privacy.
Real-memory Linux/Mac validation and existing architecture/submap limits remain.
MCP must pin this source; Workbench requires a subsequent tested backend adoption
and repackaging to embed it. It does not inherit the plugin update automatically.

---

# CryptoMem 0.4.0 (prerelease)

Adds experimental `mac.cryptomem.CryptoMem` for legacy Intel64 macOS memory
captures with exact matching Darwin kernel symbols. Reuses the bounded scanner
and BTC, Ethereum, XRP and Monero validators; no dependencies or network calls.
Windows and Linux commands, options and output schemas remain unchanged.

Selects one BSD PID through the Mac tasks queue, creates one process layer, and
scans exclusive-ended VM mappings. It rejects kernel_task/PID zero, missing maps,
unreadable data, silent map truncation, inconsistent entry counts, overlapping
ranges and exhausted limits. Nested submaps are explicitly unsupported, including
shared-region submaps in ordinary processes; these scans fail as incomplete.

The existing legacy Mac symbol pack may be reused when the captured kernel
matches. This does not imply every table or macOS build has been tested. Intel32,
Apple silicon/ARM64, and modern macOS support are not added. Upstream macOS support
is no longer actively maintained. Real-memory macOS and Linux validation remain
outstanding; see VALIDATION.md. Address occurrence is not wallet ownership.

Install the complete `plugins` tree. MCP must pin this revision in its inventory;
Workbench needs a backend pin update and repackage to embed that newer inventory.

---

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
