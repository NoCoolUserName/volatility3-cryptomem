# Opt-in formats and artifact contract (0.5.0)

`--detect-mnemonics`, `--detect-private-keys`, and `--detect-txids` independently
enable new text detectors in the existing single-process scanner. All default to
false. Address-only execution retains schema 1, filenames, columns and currency
selection. It suppresses recognizable secrets embedded in payment-request text.
No additional framework, MCP tool, network client, report, or runtime dependency
is introduced. Limits count all emitted findings and all read bytes together.

## English BIP-39

The bundled list is `bitcoin/bips` revision
`ce1862ac6bcffa1dd20aad858380e51e66e949ea`, `bip-0039/english.txt`, SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
The original bytes are the embedded `WORDS` plus one final newline; integrity is
checked before scanning. Supported lengths are 12, 15, 18, 21 and 24. Validation
applies NFKD, exact lowercase English words, 11-bit indexes and the leading
SHA-256 entropy-checksum bits. It does not derive a seed or search a passphrase.

ASCII and UTF-16LE on either byte alignment are supported. Wide text also accepts
compatibility-width Latin characters, Latin ligatures and Unicode spacing. There
is no general UTF-8/UTF-16BE decoder. Transcription whitespace is collapsed for
validation, with at most 16 normalized whitespace characters between words.
Punctuation, unrecognized words and nontext bytes break a phrase. Source offsets,
byte lengths and original spelling remain exact after normalization.

All checksum-valid windows of supported lengths in a contiguous English-word
chain are candidates. Overlapping windows may occur; `boundary_ambiguous` is true
when adjacent dictionary words leave the phrase boundary uncertain. Checksum
failures are discarded for mnemonic detection; phrase-shaped text is still
conservatively redacted from other output. Short checksums can validate ordinary
prose or public examples by chance. `example_or_test_vector` is a lexical hint,
never proof of origin. Other languages, Electrum, SLIP-39, Monero seeds and other
non-BIP-39 schemes are unsupported. A valid phrase in memory establishes neither
wallet presence nor ownership, use or control.

## Recognizable serialized private keys

Literal ASCII/Wide ASCII WIF and BIP-32 private text have token boundaries and
Base58Check validation. WIF accepts decoded version 0x80 or 0xef, a 32-byte scalar
and, for compressed WIF, the exact 0x01 marker. BIP-32 accepts only 78-byte xprv
(0x0488ade4) and tprv (0x04358394) payloads, the private 0x00 marker and root
depth/fingerprint/child-index invariants. Both require `1 <= key < secp256k1 n`.
Nonroot ancestry/derivation and chain-code origin cannot be verified from text.
Test-family bytes do not distinguish testnet, signet or regtest; compatible
prefixes do not prove a network. WIF and extended keys are distinct formats.

Recognizable candidates retain `checksum_invalid` or `malformed` failures and
`unvalidated_shape` confidence. Valid candidates have `format_valid` confidence.
No arbitrary entropy, raw 32-byte key, public extended key, encrypted wallet,
BIP-38, unrelated serialization, or imported wallet support is claimed.

## Transaction-ID candidates

A bounded 64-hex token, with optional literal `0x`, is `candidate_only` with low
confidence. An immediately preceding explicit txid/transaction-hash field raises
confidence to medium. Only recognized label text and its exact offset/length are
retained as supporting context; raw surrounding prose is not copied. Explicit
`bitcoin_txid` / `ethereum_transaction_hash` labels supply compatible chain hints;
otherwise the chain is unknown, including an unlabeled `0x` value. These labels
are untrusted memory text, not independent chain evidence. Values may instead be
hashes, identifiers, examples or keys. There is no high/confirmed classification,
transaction parsing, confirmation, payment, balance, ownership or history claim.

## Versioned files, masking and extraction

When any new detector is enabled, the scanner writes
`cryptomem-findings-v2.jsonl` and `cryptomem-scan-summary-v2.json`, both with
`schema_version: 2`. They replace schema-1 filenames only for that opt-in run.
The renderer's existing columns remain unchanged. V2 findings retain the existing
fields and add `secret`, `confidence`, `ambiguity`; mnemonic rows add `word_count`
and `boundary_ambiguous`, and transaction rows add `supporting_context` (a label
span or null). Provenance includes PID, process, layer, exact offset, byte length
and encoding. Summary adds detector flags, `secrets_extracted` and masking policy.
For richer interpretation, read v2 artifacts; the existing Reason and Validation
columns still give the format decision. No arbitrary surrounding memory is saved.

Ordinary artifacts/renderers use `[REDACTED SECRET]` for both `value` and
`canonical` in secret rows. All recognizable key candidates, including checksum
failures, are masked. Recognizable secrets in other string fields, including
percent-encoded payment messages, are suppressed. Extended-scan exceptions omit
untrusted error text; incomplete summaries, partial artifacts and cancellation
must never be interpreted as clean scans. SIGKILL can prevent a final summary.

Only explicit `--extract-secrets`, together with a secret detector, writes full
values to `cryptomem-secrets-v1.jsonl` (`schema_version: 1` per row). It retains
original `value` and normalized `canonical`, source spans and validation metadata.
This uses only Volatility's configured output handler, a fixed basename and a
regular POSIX file descriptor forced to mode 0600 before writing. Unsupported
handlers and non-POSIX extraction fail closed; ordinary masked scans still work
on Windows hosts. Standalone users must configure a private case output directory
(0700), trusted local file handler and appropriate local ACLs. No caller-selected
secret path is accepted. Volatility may suffix duplicate filenames; preserve
earlier runs. Interrupted extraction can leave a private `.vol3` temporary file.

The MCP integration refuses extraction from a shared output root and blocks all
MCP readers from secret files and unclassified extraction-run files, including
temporary output. Masked v2 findings/summary and renderer JSON remain readable.
Full extraction is for local operator access only; do not paste it into an AI
client, report, issue, CI log, screenshot or external service. File modes are not
encryption, secure deletion or a defense against a privileged local account.

Overlap/lookahead remains bounded by the existing 4,096-byte artifact bound;
supported phrase spans and label context fit inside it. Bytes never cross mapping
boundaries or unreadable gaps. Coverage applies only to enumerated process
mappings; unsupported architectures, missing symbols and read/limit failures
remain explicit. Linux thread leaders and Mac nested-submap restrictions remain.
