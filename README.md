# philiprehberger-log_filter

[![Tests](https://github.com/philiprehberger/rb-log-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-log-filter/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-log_filter.svg)](https://rubygems.org/gems/philiprehberger-log_filter)

Pattern-based log filtering with drop, replace, and preset rules.

## Requirements

- Ruby >= 3.1

## Installation

Add to your Gemfile:

```ruby
gem "philiprehberger-log_filter"
```

Then run:

```bash
bundle install
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
filter = Philiprehberger::LogFilter::Filter.new
  .drop_if { |msg| msg.length > 1000 }   # drop excessively long messages
  .drop_if { |msg| msg.count("\n") > 10 } # drop multi-line spam
```

## API

| Class / Method | Description |
|----------------|-------------|
| `Filter.new` | Create a new empty filter chain |
| `Filter#drop(pattern)` | Add a regex drop rule; returns self |
| `Filter#drop_if(&block)` | Add a block-based drop rule; returns self |
| `Filter#replace(pattern, replacement)` | Add a replacement rule; returns self |
| `Filter#apply(message)` | Run all rules; returns transformed string or nil |
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
bundle exec rspec      # Run tests
bundle exec rubocop    # Check code style
```

## License

MIT
