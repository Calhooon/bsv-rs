# Header vectors

Raw 80-byte frames in ascending height order, from Teranode v0.16.0
(`4edb60a40c6628ff0ef60231c2628efd7103fde5`), as carried by
chaintracks-cloudflare@db4008d `src/testdata/README.md:1-23`.
The sibling pin is bsv-script-lean@50d437b `docs/PROVENANCE.md`.

| File | Source at the Teranode pin | SHA-256 |
| --- | --- | --- |
| main_501984_504031.bin | services/blockchain/testdata/mainnet_headers_477792_504031.bin, final 163840 bytes | 48999616d05872e958709c1ac964022d0979394e348a0a1013d87b6a3b40ca35 |
| main_886001_888000.bin | services/blockchain/886001_888000_headers.bin, whole | 106deacffa0eba0db49f814f1c3672222a81f792e514bf343478dcf055385bd9 |
| test_0_547.bin | services/blockchain/testdata/testnet_headers_0_547.bin, whole | 8a6ba287b6a64cff223c4ffadccce85f8af292ad2a13b1427f20534083f9100e |

`tests/chain_primitives.rs` pins these hashes, checks every frame, parent link,
proof of work and compact round trip, and checks each run's accumulated work
and terminal block hash. The design probe's source is not included.
