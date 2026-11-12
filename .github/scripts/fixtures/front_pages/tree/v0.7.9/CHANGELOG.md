# Changelog

## [0.7.9] - 2026-11-21

### Fixed: Other::read refuses a short frame, a back-patch of the 0.7 line (#905)

- Migration. A caller that read a short frame now gets an `Err`.

## [0.7.8] - 2026-10-01
