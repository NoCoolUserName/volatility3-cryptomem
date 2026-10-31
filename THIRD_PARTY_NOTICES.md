# Attribution and scope

CryptoMem is an independently maintained implementation published under the Volatility Software License 1.0. The source for each release
is available at https://github.com/NoCoolUserName/volatility3-cryptomem.

## CryptoScan reference

[BoB10th-BTC/CryptoScan](https://github.com/BoB10th-BTC/CryptoScan), reviewed at
commit `9588ff800ba625f7ef044ddb98a23013810fbf29`, supplied the initial research
direction: cryptocurrency text artifacts in Windows process memory. Its main
source credits MoonGyu Lee and JeongYoon Kang and carries a Volatility Foundation
VSL-1.0 notice. CryptoMem does not bundle or execute that implementation, wordlist,
artwork, reports, network-enrichment code, or dependencies. No upstream regex or
implementation source was copied. Inspiration is not endorsement or feature parity.

## Format specifications and public test vectors

- [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki):
  Pieter Wuille and Greg Maxwell, 2017, BSD-2-Clause.
- [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki):
  Pieter Wuille, 2020, BSD-2-Clause. Published valid/invalid address vectors are
  used in tests. Protocol constants and validation rules follow these documents;
  reference-implementation code was not copied.
- [BIP-321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki):
  Matt Corallo, 2024, BSD-2-Clause. Only the documented direct-address subset is
  interpreted; no full payment-handler implementation is claimed.
- [ERC-55](https://eips.ethereum.org/EIPS/eip-55): Vitalik Buterin and Alex Van
  de Sande, 2016, CC0. Public address examples and checksum specification.
- [ERC-681](https://eips.ethereum.org/EIPS/eip-681): Daniel A. Nagy, 2017, CC0.
  Direct-address request syntax; contract calls and ENS resolution are unsupported.
- [XRPL classic address documentation](https://xrpl.org/docs/concepts/accounts/addresses)
  and protocol Base58 alphabet/payload definitions. Protocol rules informed an
  original validator; no XRPL library implementation is bundled.

The BSD-2-Clause terms for retained Bitcoin specification/test-vector material
are included in LICENSE along with the author attribution above. CC0 material:
https://creativecommons.org/publicdomain/zero/1.0/.

## Runtime dependencies

BIP-39 English word list: Bitcoin BIPs contributors, Marek Palatinus, Pavol
Rusnak, Aaron Voisine and Sean Bowe, MIT. Pinned revision and digest are recorded
in EXTENDED_FORMATS.md and the embedded module. BIP-39 public zero-entropy phrase
and BIP-32 vector 1 are synthetic/public test material. BIP-32: Pieter Wuille,
BSD-2-Clause (terms retained in LICENSE). WIF rules were checked against Bitcoin
Core's `src/key_io.cpp`; no wallet implementation code is copied. The original
validators follow [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
and [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

Monero address format references: [standard addresses](https://docs.getmonero.org/public-address/standard-address/),
[subaddresses](https://docs.getmonero.org/public-address/subaddress/),
[integrated addresses](https://docs.getmonero.org/public-address/integrated-address/),
and [block Base58](https://docs.getmonero.org/cryptography/base58/).
The public standard/integrated examples used in tests come from Monero Docs,
copyright Monero Community, under MIT; their terms are retained in LICENSE.
Network/type constants were checked against
[Monero's configuration](https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h).
The decoder is an original implementation; no Monero implementation code is copied.

Volatility 3 2.28.2 retains its upstream VSL and notices. PyCryptodome 3.23.0
supplies Keccak (Ethereum and Monero use Keccak-256, not SHA3-256); it retains its own public
domain/BSD notices. The standalone repository distributes neither dependency's
binaries. `requirements.txt` pins the tested runtime. Retain the exact dependency
licenses if redistributing an environment or binary bundle.
