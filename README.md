# philiprehberger-log_filter

[![Tests](https://github.com/philiprehberger/rb-log-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-log-filter/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-log_filter.svg)](https://rubygems.org/gems/philiprehberger-log_filter)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rb-log-filter)](https://github.com/philiprehberger/rb-log-filter/commits/main)

Pattern-based log filtering with drop, replace, and preset rules

## Requirements

- Ruby >= 3.1

## Installation

Add to your Gemfile:

```ruby
gem "philiprehberger-log_filter"
```

Or install directly:

```bash
gem install philiprehberger-log_filter
```

## Usage

```ruby
require "philiprehberger/log_filter"

# Build a custom filter chain
filter = Philiprehberger::LogFilter::Filter.new
  .drop(/health_?check/i)
  .drop(/DEBUG/)
  .replace(/password=\S+/, "password=[REDACTED]")

filter.apply("GET /healthcheck 200")       # => nil (dropped)
filter.apply("DEBUG some noise")            # => nil (dropped)
filter.apply("login password=abc123")       # => "login password=[REDACTED]"
filter.apply("GET /api/users 200")          # => "GET /api/users 200"
```

### Wrapping a Logger

```ruby
require "logger"
require "philiprehberger/log_filter"

logger = Logger.new($stdout)
filter = Philiprehberger::LogFilter::Filter.new
  .drop(/healthcheck/i)
  .replace(/token=\S+/, "token=[REDACTED]")

filtered_logger = Philiprehberger::LogFilter.wrap(logger, filter)

filtered_logger.info("GET /healthcheck 200")    # silently dropped
filtered_logger.info("auth token=secret123")     # logs "auth token=[REDACTED]"
filtered_logger.info("GET /api/users 200")       # logs normally
```

### Using Presets

```ruby
require "philiprehberger/log_filter"

# Drop health-check noise
filter = Philiprehberger::LogFilter.health_check_filter
filtered_logger = Philiprehberger::LogFilter.wrap(logger, filter)

# Drop static asset requests
filter = Philiprehberger::LogFilter.asset_filter

# Drop bot/crawler traffic
filter = Philiprehberger::LogFilter.bot_filter
```

### Block-Based Drop Rules

```ruby
require "philiprehberger/log_filter"

filter = Philiprehberger::LogFilter::Filter.new
  .drop_if { |msg| msg.length > 1000 }   # drop excessively long messages
  .drop_if { |msg| msg.count("\n") > 10 } # drop multi-line spam
```

### Sampling

```ruby
require "philiprehberger/log_filter"

# Only pass through 10% of debug messages
filter = Philiprehberger::LogFilter::Filter.new
  .sample(/DEBUG/, rate: 0.1)

filter.apply("DEBUG verbose output")  # => nil (90% of the time)
filter.apply("INFO normal message")   # => "INFO normal message" (always passes)
```

### Structured Log Support

```ruby
require "philiprehberger/log_filter"

filter = Philiprehberger::LogFilter::Filter.new
  .drop_field("password")
  .mask_field("ssn", with: "***")

filter.apply('{"user":"alice","password":"secret","ssn":"123-45-6789"}')
# => '{"user":"alice","ssn":"***"}'

# Non-JSON messages pass through unmodified
filter.apply("plain text log line")  # => "plain text log line"
```

### Chaining filters

Compose two filters into a new filter whose `apply` pipes each event through
the first filter and then through the second. If the first filter drops the
event (returns `nil`), the second is skipped. Composition is associative, so
`a.chain(b).chain(c)` works as expected.

```ruby
require "philiprehberger/log_filter"

redact = Philiprehberger::LogFilter::Filter.new
  .replace(/password=\S+/, "password=[REDACTED]")

drop_debug = Philiprehberger::LogFilter::Filter.new
  .drop(/DEBUG/)

pipeline = drop_debug.chain(redact)

pipeline.apply("DEBUG noise")                     # => nil (dropped by first filter)
pipeline.apply("login password=abc123")           # => "login password=[REDACTED]"
```

The chained filter tracks its own `stats` independently of the source filters.

### Filter Statistics

```ruby
require "philiprehberger/log_filter"

filter = Philiprehberger::LogFilter::Filter.new
  .drop(/DEBUG/)
  .replace(/secret/, "[REDACTED]")

filter.apply("DEBUG noise")
filter.apply("has secret data")
filter.apply("normal message")

filter.stats  # => { dropped: 1, passed: 2, replaced: 1, sampled: 0 }
filter.reset_stats!
filter.stats  # => { dropped: 0, passed: 0, replaced: 0, sampled: 0 }
```

## API

| Class / Method | Description |
|----------------|-------------|
| `Filter.new` | Create a new empty filter chain |
| `Filter#drop(pattern)` | Add a regex drop rule; returns self |
| `Filter#drop_if(&block)` | Add a block-based drop rule; returns self |
| `Filter#replace(pattern, replacement)` | Add a replacement rule; returns self |
| `Filter#sample(pattern, rate:)` | Add a sampling rule; only pass rate fraction of matches |
| `Filter#drop_field(key)` | Remove a field from JSON log messages; returns self |
| `Filter#mask_field(key, with:)` | Mask a field value in JSON log messages; returns self |
| `Filter#apply(message)` | Run all rules; returns transformed string or nil |
| `Filter#chain(other)` | Compose with another filter; returns a new filter piping events through both |
| `Filter#stats` | Return counters: dropped, passed, replaced, sampled |
| `Filter#reset_stats!` | Zero all statistics counters |
| `Wrapper.new(logger, filter)` | Wrap a Logger with a filter |
| `Presets.health_check` | Filter dropping health-check paths |
| `Presets.assets` | Filter dropping static-asset requests |
| `Presets.bots` | Filter dropping bot/crawler traffic |
| `LogFilter.wrap(logger, filter)` | Convenience wrapper constructor |
| `LogFilter.health_check_filter` | Shortcut for `Presets.health_check` |
| `LogFilter.asset_filter` | Shortcut for `Presets.assets` |
| `LogFilter.bot_filter` | Shortcut for `Presets.bots` |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rb-log-filter)

🐛 [Report issues](https://github.com/philiprehberger/rb-log-filter/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rb-log-filter/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
