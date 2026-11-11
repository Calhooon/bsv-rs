# Changelog

## [Unreleased]

### Fixed: an unreleased entry that no page may carry (#999)

## [0.8.7] - 2026-11-20

### Fixed: Thing::read refuses bytes after the thing, as the reference does (#901)

The reader kept them.

- Migration. A caller that passed bytes after the thing now gets an `Err`. No public type or signature changes.

### Notes: cross-SDK parity (#901)

The other side reads a prefix.

### Changed

- The gate runs the page script's tests on every pull request (#902). It ran them at the tag alone.
- The reconciler names each gap (#903).

## [0.8.6] - 2026-11-11

### Fixed: an older entry (#800)
