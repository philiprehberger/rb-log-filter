# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-03-13

### Fixed
- Fix RuboCop ExtraSpacing offense in gemspec metadata

## [0.1.0] - 2026-03-13

### Added
- Initial release
- `Filter` class with `#drop`, `#drop_if`, and `#replace` rules
- `Wrapper` class for wrapping Ruby Logger with filter support
- `Presets` module with `health_check`, `assets`, and `bots` factory methods
- Convenience methods on `Philiprehberger::LogFilter` module
