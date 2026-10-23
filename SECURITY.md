# Security

Treat memory, recovered strings, process names, and output as untrusted evidence.
CryptoMem performs bounded local reads and never follows recovered URLs, invokes
a wallet, broadcasts a transaction, or executes recovered code. Run against an
authorized acquisition copy and retain its independent acquisition hash.

The plugin is not a sandbox for other installed Volatility plugins. Standalone
users should use Volatility `--offline` and provision matching symbols locally.
MCP integrations retain their own process timeout, cancellation, hashing, and
case confinement. Direct Volatility CLI users manage those host controls.

Report suspected vulnerabilities through GitHub private vulnerability reporting
when available. Do not attach private evidence or secrets to public issues.
