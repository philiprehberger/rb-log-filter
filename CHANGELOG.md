# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-05-29

### Added
- `Filter#tap_each(&block)` — invoke the block with every message that reaches the rule; message is forwarded unchanged. Useful for instrumentation and counters.
- `Presets.urls_only` and `LogFilter.urls_only_filter` shortcut — drop everything that isn't a standard HTTP request-line entry (`GET /…`, `POST /…`, etc.).

## [0.5.0] - 2026-05-12

### Added
- `Filter#truncate(max_length, suffix:)` caps outgoing messages at `max_length` characters and appends the suffix when truncation occurred; chainable

## [0.4.0] - 2026-04-30

### Added
- `Presets.pii` — redacts emails, US Social Security Numbers, and 13–19 digit credit-card-shaped numbers with `[REDACTED]`
- `Presets.secrets` — redacts `Bearer` tokens, `api_key=`/`access_token=` parameters, and AWS-style access key IDs (`AKIA…`) with `[REDACTED]`

## [0.3.0] - 2026-04-17

### Added
- `Filter#chain(other)` composes two filters into a new filter that pipes events through both in order (drops short-circuit)

## [0.2.1] - 2026-03-31

### Changed
- Standardize README badges, support section, and license format

## [0.2.0] - 2026-03-29

### Added

- Sampling support via `Filter#sample(pattern, rate:)` — pass through only a fraction of matching messages
- Filter statistics via `Filter#stats` and `Filter#reset_stats!` — thread-safe atomic counters for dropped, passed, replaced, and sampled messages
- Structured log support via `Filter#drop_field(key)` and `Filter#mask_field(key, with:)` — parse JSON messages, remove or mask fields, re-serialize

## [0.1.7] - 2026-03-26

### Changed

- Add Sponsor badge and fix License link format in README

## [0.1.6] - 2026-03-24

### Fixed
- Fix README one-liner to remove trailing period

## [0.1.5] - 2026-03-24

### Fixed
- Remove inline comments from Development section to match template

## [0.1.4] - 2026-03-22

### Changed
- Expand test coverage

## [0.1.3] - 2026-03-16

### Changed
- Add License badge to README
- Add bug_tracker_uri to gemspec

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
