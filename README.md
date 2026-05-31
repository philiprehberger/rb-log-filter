# philiprehberger-log_filter

[![Tests](https://github.com/philiprehberger/rb-log-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-log-filter/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-log_filter.svg)](https://rubygems.org/gems/philiprehberger-log_filter)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rb-log-filter)](https://github.com/philiprehberger/rb-log-filter/commits/main)

![philiprehberger-log_filter](https://raw.githubusercontent.com/philiprehberger/rb-log-filter/main/package-card.webp)

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

### PII and Secret Redaction Presets

```ruby
require "philiprehberger/log_filter"

pii = Philiprehberger::LogFilter::Presets.pii
pii.apply("login user=alice@example.com")     # => "login user=[REDACTED]"
pii.apply("SSN 123-45-6789 lookup")           # => "SSN [REDACTED] lookup"
pii.apply("card 4242424242424242 charged")    # => "card [REDACTED] charged"

secrets = Philiprehberger::LogFilter::Presets.secrets
secrets.apply("Authorization: Bearer abc.def-_xyz")  # => "Authorization: Bearer [REDACTED]"
secrets.apply("GET /v1?api_key=sk_live_xyz123 200")  # => "GET /v1?api_key=[REDACTED] 200"
secrets.apply("AKIAIOSFODNN7EXAMPLE in env")          # => "[REDACTED] in env"
```

### Inspecting Messages with tap_each

Insert a side-effecting hook into the pipeline. The block runs for every message that reaches its position (after any previous transforms); its return value is ignored.

```ruby
require "philiprehberger/log_filter"

count = 0
filter = Philiprehberger::LogFilter::Filter.new
  .replace(/secret/, "[REDACTED]")
  .tap_each { |msg| count += 1 if msg.length > 100 }

filter.apply("short")
filter.apply("a" * 200)
count  # => 1
```

### Keeping Only HTTP Request Lines

```ruby
require "philiprehberger/log_filter"

filter = Philiprehberger::LogFilter.urls_only_filter
filter.apply("GET /api/users 200")  # => "GET /api/users 200"
filter.apply("worker booted")       # => nil
```

### Debugging filters with `explain`

When a filter chain isn't behaving as expected, use `#describe_rules` to dump the configuration and `#explain(message)` to trace how a specific message flows through. `#explain` is side-effect-free — it does NOT mutate `#stats` and does NOT invoke `tap_each` blocks. Sample rules are treated deterministically (a match counts as `:sampled_in`) so traces are reproducible.

```ruby
require "philiprehberger/log_filter"

filter = Philiprehberger::LogFilter::Filter.new
  .drop(/DEBUG/)
  .replace(/password=\S+/, "password=[REDACTED]")
  .mask_field("ssn")

filter.describe_rules
# => [
#   { type: :drop_pattern, description: "drop matching /DEBUG/" },
#   { type: :replace,      description: "replace /password=\\S+/ with \"password=[REDACTED]\"" },
#   { type: :mask_field,   description: "mask field \"ssn\" with \"***\"" }
# ]

filter.explain("user login password=abc123")
# => {
#   result: "user login password=[REDACTED]",
#   decisions: [
#     { rule: 0, type: :drop_pattern, matched: false, action: :passed },
#     { rule: 1, type: :replace,      matched: true,  action: :replaced },
#     { rule: 2, type: :mask_field,   matched: false, action: :unchanged }
#   ]
# }

filter.explain("DEBUG noisy line")
# => {
#   result: nil,
#   decisions: [
#     { rule: 0, type: :drop_pattern, matched: true, action: :dropped }
#   ]
# }
```

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
| `Filter#truncate(max_length, suffix:)` | Truncate outgoing messages longer than max_length and append the suffix; returns self |
| `Filter#tap_each(&block)` | Invoke the block with every message passing through; message is forwarded unchanged; returns self |
| `Filter#apply(message)` | Run all rules; returns transformed string or nil |
| `Filter#chain(other)` | Compose with another filter; returns a new filter piping events through both |
| `Filter#describe_rules` | Return an array of `{type:, description:}` hashes describing every rule in order |
| `Filter#explain(message)` | Trace how a message flows through the chain without mutating stats or invoking tap blocks; returns `{result:, decisions:}` |
| `Filter#stats` | Return counters: dropped, passed, replaced, sampled |
| `Filter#reset_stats!` | Zero all statistics counters |
| `Wrapper.new(logger, filter)` | Wrap a Logger with a filter |
| `Presets.health_check` | Filter dropping health-check paths |
| `Presets.assets` | Filter dropping static-asset requests |
| `Presets.bots` | Filter dropping bot/crawler traffic |
| `Presets.urls_only` | Filter that keeps only HTTP request-line entries (`GET /…`, `POST /…`, …) and drops everything else |
| `Presets.pii` | Filter redacting emails, SSNs, and credit-card-shaped numbers with `[REDACTED]` |
| `Presets.secrets` | Filter redacting Bearer tokens, `api_key=`/`access_token=` values, and AWS access keys |
| `LogFilter.wrap(logger, filter)` | Convenience wrapper constructor |
| `LogFilter.health_check_filter` | Shortcut for `Presets.health_check` |
| `LogFilter.asset_filter` | Shortcut for `Presets.assets` |
| `LogFilter.bot_filter` | Shortcut for `Presets.bots` |
| `LogFilter.urls_only_filter` | Shortcut for `Presets.urls_only` |

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
