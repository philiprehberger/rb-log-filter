# frozen_string_literal: true

require 'spec_helper'
require 'logger'
require 'json'

RSpec.describe Philiprehberger::LogFilter do
  it 'has a version number' do
    expect(Philiprehberger::LogFilter::VERSION).not_to be_nil
  end

  describe Philiprehberger::LogFilter::Filter do
    subject(:filter) { described_class.new }

    describe '#drop' do
      it 'suppresses messages matching the pattern' do
        filter.drop(/secret/)
        expect(filter.apply('this is secret data')).to be_nil
      end

      it 'passes messages that do not match' do
        filter.drop(/secret/)
        expect(filter.apply('this is public data')).to eq('this is public data')
      end
    end

    describe '#drop_if' do
      it 'suppresses messages when the block returns true' do
        filter.drop_if { |msg| msg.length > 10 }
        expect(filter.apply('a long message here')).to be_nil
      end

      it 'passes messages when the block returns false' do
        filter.drop_if { |msg| msg.length > 100 }
        expect(filter.apply('short')).to eq('short')
      end
    end

    describe '#replace' do
      it 'transforms content matching the pattern' do
        filter.replace(/password=\S+/, 'password=[REDACTED]')
        expect(filter.apply('user login password=abc123')).to eq('user login password=[REDACTED]')
      end
    end

    describe '#apply' do
      it 'chains multiple rules in order' do
        filter.drop(/debug/).replace(/secret/, '[REDACTED]')

        expect(filter.apply('debug info')).to be_nil
        expect(filter.apply('has secret value')).to eq('has [REDACTED] value')
        expect(filter.apply('normal message')).to eq('normal message')
      end
    end

    describe 'chaining syntax' do
      it 'supports fluent chaining' do
        result = described_class.new
                                .drop(/foo/)
                                .drop(/bar/)
                                .replace(/secret/, '[REDACTED]')

        expect(result).to be_a(described_class)
        expect(result.apply('foo')).to be_nil
        expect(result.apply('bar')).to be_nil
        expect(result.apply('my secret plan')).to eq('my [REDACTED] plan')
        expect(result.apply('hello')).to eq('hello')
      end
    end

    describe '#rules' do
      it 'returns an empty array for a new filter' do
        expect(filter.rules).to eq([])
      end

      it 'accumulates rules in order' do
        filter.drop(/a/).replace(/b/, 'c').drop_if { |_| false }
        expect(filter.rules.size).to eq(3)
        expect(filter.rules[0][:type]).to eq(:drop_pattern)
        expect(filter.rules[1][:type]).to eq(:replace)
        expect(filter.rules[2][:type]).to eq(:drop_block)
      end
    end

    describe 'drop rule ordering matters' do
      it 'applies replace before drop when replace is first' do
        filter.replace(/secret/, 'open').drop(/open/)
        expect(filter.apply('this is secret')).to be_nil
      end

      it 'drops before replace when drop is first' do
        filter.drop(/secret/).replace(/open/, 'closed')
        expect(filter.apply('this is secret')).to be_nil
      end
    end

    describe 'empty message' do
      it 'returns empty string for empty input' do
        filter.drop(/something/)
        expect(filter.apply('')).to eq('')
      end
    end

    describe 'multiple replacements in one message' do
      it 'replaces all occurrences of the pattern' do
        filter.replace(/\d+/, 'NUM')
        expect(filter.apply('order 123 item 456')).to eq('order NUM item NUM')
      end
    end

    describe 'drop_if with complex logic' do
      it 'can use multi-condition logic in block' do
        filter.drop_if { |msg| msg.include?('error') && msg.include?('timeout') }
        expect(filter.apply('error: timeout occurred')).to be_nil
        expect(filter.apply('error: bad input')).to eq('error: bad input')
        expect(filter.apply('timeout warning')).to eq('timeout warning')
      end
    end

    describe 'no rules applied' do
      it 'returns message unchanged when no rules exist' do
        expect(filter.apply('any message')).to eq('any message')
      end
    end

    describe 'case-insensitive patterns' do
      it 'supports case-insensitive regex' do
        filter.drop(/SECRET/i)
        expect(filter.apply('this is Secret data')).to be_nil
        expect(filter.apply('this is secret data')).to be_nil
      end
    end

    # --- Sampling ---

    describe '#sample' do
      it 'returns self for chaining' do
        result = filter.sample(/debug/, rate: 0.5)
        expect(result).to be filter
      end

      it 'raises ArgumentError for rate below 0.0' do
        expect { filter.sample(/debug/, rate: -0.1) }.to raise_error(ArgumentError)
      end

      it 'raises ArgumentError for rate above 1.0' do
        expect { filter.sample(/debug/, rate: 1.5) }.to raise_error(ArgumentError)
      end

      it 'passes non-matching messages through unaffected' do
        filter.sample(/debug/, rate: 0.0)
        expect(filter.apply('info: normal message')).to eq('info: normal message')
      end

      it 'drops all matching messages when rate is 0.0' do
        filter.sample(/debug/, rate: 0.0)
        10.times do
          expect(filter.apply('debug: some noise')).to be_nil
        end
      end

      it 'passes all matching messages when rate is 1.0' do
        filter.sample(/debug/, rate: 1.0)
        10.times do
          expect(filter.apply('debug: some noise')).to eq('debug: some noise')
        end
      end

      it 'passes approximately the correct fraction of matching messages' do
        filter.sample(/debug/, rate: 0.5)
        allow(SecureRandom).to receive(:rand).and_return(0.3, 0.7, 0.1, 0.9, 0.4)

        results = 5.times.map { filter.apply('debug: message') }
        passed = results.compact.count
        dropped = results.count(nil)

        expect(passed).to eq(3)
        expect(dropped).to eq(2)
      end

      it 'increments sampled stat for passed matching messages' do
        filter.sample(/debug/, rate: 1.0)
        filter.apply('debug: message')
        expect(filter.stats[:sampled]).to eq(1)
      end

      it 'increments dropped stat for dropped matching messages' do
        filter.sample(/debug/, rate: 0.0)
        filter.apply('debug: message')
        expect(filter.stats[:dropped]).to eq(1)
      end

      it 'adds a sample rule to the rules list' do
        filter.sample(/debug/, rate: 0.5)
        expect(filter.rules.last[:type]).to eq(:sample)
      end
    end

    # --- Filter Statistics ---

    describe '#stats' do
      it 'returns initial zeroed stats' do
        expect(filter.stats).to eq({ dropped: 0, passed: 0, replaced: 0, sampled: 0 })
      end

      it 'returns a copy of the stats hash' do
        stats = filter.stats
        stats[:dropped] = 999
        expect(filter.stats[:dropped]).to eq(0)
      end

      it 'increments passed counter on successful apply' do
        filter.apply('hello')
        expect(filter.stats[:passed]).to eq(1)
      end

      it 'increments dropped counter when a message is dropped' do
        filter.drop(/secret/)
        filter.apply('secret data')
        expect(filter.stats[:dropped]).to eq(1)
      end

      it 'increments replaced counter when a replacement occurs' do
        filter.replace(/foo/, 'bar')
        filter.apply('foo baz')
        expect(filter.stats[:replaced]).to eq(1)
      end

      it 'does not increment replaced counter when no replacement occurs' do
        filter.replace(/foo/, 'bar')
        filter.apply('baz qux')
        expect(filter.stats[:replaced]).to eq(0)
      end

      it 'tracks multiple operations correctly' do
        filter.drop(/drop_me/).replace(/secret/, '[REDACTED]')

        filter.apply('drop_me please')
        filter.apply('has secret info')
        filter.apply('normal message')

        expect(filter.stats[:dropped]).to eq(1)
        expect(filter.stats[:replaced]).to eq(1)
        expect(filter.stats[:passed]).to eq(2)
      end

      it 'is thread-safe' do
        threads = 10.times.map do
          Thread.new do
            100.times { filter.apply('message') }
          end
        end
        threads.each(&:join)
        expect(filter.stats[:passed]).to eq(1000)
      end
    end

    describe '#reset_stats!' do
      it 'zeroes all counters' do
        filter.drop(/secret/)
        filter.apply('secret data')
        filter.apply('normal data')

        filter.reset_stats!
        expect(filter.stats).to eq({ dropped: 0, passed: 0, replaced: 0, sampled: 0 })
      end
    end

    # --- Structured Log Support ---

    describe '#drop_field' do
      it 'returns self for chaining' do
        result = filter.drop_field('password')
        expect(result).to be filter
      end

      it 'removes the specified field from a JSON message' do
        filter.drop_field('password')
        input = JSON.generate({ 'user' => 'alice', 'password' => 'secret123' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice' })
      end

      it 'passes through JSON messages that do not contain the field' do
        filter.drop_field('password')
        input = JSON.generate({ 'user' => 'alice' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice' })
      end

      it 'passes non-JSON messages through unmodified' do
        filter.drop_field('password')
        expect(filter.apply('plain text message')).to eq('plain text message')
      end

      it 'passes non-object JSON through unmodified' do
        filter.drop_field('password')
        expect(filter.apply('[1, 2, 3]')).to eq('[1, 2, 3]')
      end

      it 'accepts symbol keys by converting to string' do
        filter.drop_field(:password)
        input = JSON.generate({ 'password' => 'secret123', 'user' => 'alice' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice' })
      end

      it 'can remove multiple fields with chaining' do
        filter.drop_field('password').drop_field('token')
        input = JSON.generate({ 'user' => 'alice', 'password' => 'secret', 'token' => 'abc' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice' })
      end
    end

    describe '#mask_field' do
      it 'returns self for chaining' do
        result = filter.mask_field('password')
        expect(result).to be filter
      end

      it 'masks the specified field with default mask' do
        filter.mask_field('password')
        input = JSON.generate({ 'user' => 'alice', 'password' => 'secret123' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice', 'password' => '***' })
      end

      it 'masks the specified field with custom mask' do
        filter.mask_field('email', with: '[REDACTED]')
        input = JSON.generate({ 'user' => 'alice', 'email' => 'alice@example.com' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice', 'email' => '[REDACTED]' })
      end

      it 'passes through JSON messages that do not contain the field' do
        filter.mask_field('password')
        input = JSON.generate({ 'user' => 'alice' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'user' => 'alice' })
      end

      it 'does not increment replaced stat when field is absent' do
        filter.mask_field('password')
        filter.apply(JSON.generate({ 'user' => 'alice' }))
        expect(filter.stats[:replaced]).to eq(0)
      end

      it 'increments replaced stat when field is masked' do
        filter.mask_field('password')
        filter.apply(JSON.generate({ 'password' => 'secret' }))
        expect(filter.stats[:replaced]).to eq(1)
      end

      it 'passes non-JSON messages through unmodified' do
        filter.mask_field('password')
        expect(filter.apply('plain text message')).to eq('plain text message')
      end

      it 'passes non-object JSON through unmodified' do
        filter.mask_field('password')
        expect(filter.apply('"just a string"')).to eq('"just a string"')
      end

      it 'accepts symbol keys by converting to string' do
        filter.mask_field(:password, with: 'XXX')
        input = JSON.generate({ 'password' => 'secret123' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'password' => 'XXX' })
      end
    end

    describe '#truncate' do
      it 'returns self for chaining' do
        result = filter.truncate(50)
        expect(result).to be filter
      end

      it 'passes through messages shorter than max_length unchanged' do
        filter.truncate(20)
        expect(filter.apply('short message')).to eq('short message')
      end

      it 'passes through messages exactly max_length unchanged' do
        filter.truncate(5)
        expect(filter.apply('hello')).to eq('hello')
      end

      it 'truncates messages longer than max_length and appends default suffix' do
        filter.truncate(10)
        result = filter.apply('hello world, this is too long')
        expect(result.length).to eq(10)
        expect(result).to end_with('…')
        expect(result).to eq('hello wor…')
      end

      it 'appends a custom suffix when provided' do
        filter.truncate(10, suffix: '...')
        result = filter.apply('hello world, this is too long')
        expect(result.length).to eq(10)
        expect(result).to eq('hello w...')
      end

      it 'raises ArgumentError when max_length is zero' do
        expect { filter.truncate(0) }.to raise_error(ArgumentError)
      end

      it 'raises ArgumentError when max_length is negative' do
        expect { filter.truncate(-5) }.to raise_error(ArgumentError)
      end

      it 'raises ArgumentError when max_length is not an Integer' do
        expect { filter.truncate(10.5) }.to raise_error(ArgumentError)
        expect { filter.truncate('10') }.to raise_error(ArgumentError)
        expect { filter.truncate(nil) }.to raise_error(ArgumentError)
      end

      it 'composes with drop rules — drop still drops' do
        filter.drop(/secret/).truncate(10)
        expect(filter.apply('this has secret data')).to be_nil
      end

      it 'composes with drop rules — passing messages still get truncated' do
        filter.drop(/secret/).truncate(10)
        result = filter.apply('this is a normal long message')
        expect(result.length).to eq(10)
        expect(result).to end_with('…')
      end

      it 'composes with replace rules' do
        filter.replace(/password=\S+/, 'password=[REDACTED]').truncate(20)
        result = filter.apply('user login password=abc123 long extra tail')
        expect(result.length).to eq(20)
        expect(result).to end_with('…')
      end

      it 'never drops a message — only transforms it' do
        filter.truncate(3)
        expect(filter.apply('much longer than three')).not_to be_nil
      end

      it 'handles suffix.length equal to max_length by returning suffix truncated to max_length' do
        filter.truncate(3, suffix: '...')
        result = filter.apply('a long string')
        expect(result).to eq('...')
      end

      it 'handles suffix.length greater than max_length by returning suffix truncated to max_length' do
        filter.truncate(2, suffix: '...')
        result = filter.apply('a long string')
        expect(result).to eq('..')
      end

      it 'adds a truncate rule to the rules list' do
        filter.truncate(50)
        expect(filter.rules.last[:type]).to eq(:truncate)
      end
    end

    describe '#chain' do
      it 'returns a new Filter instance' do
        a = described_class.new.drop(/foo/)
        b = described_class.new.replace(/bar/, 'baz')
        chained = a.chain(b)

        expect(chained).to be_a(Philiprehberger::LogFilter::Filter)
        expect(chained).not_to be a
        expect(chained).not_to be b
      end

      it 'does not mutate either source filter' do
        a = described_class.new.drop(/foo/)
        b = described_class.new.replace(/bar/, 'baz')
        a_rules_before = a.rules.dup
        b_rules_before = b.rules.dup

        a.chain(b)

        expect(a.rules).to eq(a_rules_before)
        expect(b.rules).to eq(b_rules_before)
      end

      it 'pipes the output of the first filter through the second' do
        a = described_class.new.mask_field('password')
        b = described_class.new.drop_field('debug')

        input = JSON.generate({ 'user' => 'alice', 'password' => 'secret', 'debug' => 'verbose' })
        result = JSON.parse(a.chain(b).apply(input))

        expect(result).to eq({ 'user' => 'alice', 'password' => '***' })
      end

      it 'short-circuits when the first filter drops the event' do
        a = described_class.new.drop(/secret/)
        b = described_class.new.replace(/./, 'X')
        allow(b).to receive(:apply).and_call_original

        chained = a.chain(b)

        expect(chained.apply('this is secret')).to be_nil
        expect(b).not_to have_received(:apply)
      end

      it 'returns nil when the second filter drops the event' do
        a = described_class.new.replace(/foo/, 'bar')
        b = described_class.new.drop(/bar/)

        expect(a.chain(b).apply('foo input')).to be_nil
      end

      it 'is equivalent to calling b.apply(a.apply(event))' do
        a = described_class.new.replace(/secret/, '[REDACTED]')
        b = described_class.new.replace(/\[REDACTED\]/, '###')

        input = 'my secret value'
        expected = b.apply(a.apply(input))

        a2 = described_class.new.replace(/secret/, '[REDACTED]')
        b2 = described_class.new.replace(/\[REDACTED\]/, '###')
        expect(a2.chain(b2).apply(input)).to eq(expected)
      end

      it 'composes associatively for three filters' do
        a = described_class.new.replace(/a/, 'A')
        b = described_class.new.replace(/b/, 'B')
        c = described_class.new.replace(/c/, 'C')

        left_assoc = a.chain(b).chain(c).apply('abc')
        right_assoc = a.chain(b.chain(c)).apply('abc')

        expect(left_assoc).to eq('ABC')
        expect(right_assoc).to eq('ABC')
      end

      it 'raises ArgumentError when given a non-Filter argument' do
        a = described_class.new

        expect { a.chain('not a filter') }.to raise_error(ArgumentError)
        expect { a.chain(nil) }.to raise_error(ArgumentError)
        expect { a.chain(42) }.to raise_error(ArgumentError)
      end

      it 'tracks stats independently on the chained filter' do
        a = described_class.new.drop(/drop/)
        b = described_class.new.replace(/foo/, 'bar')
        chained = a.chain(b)

        chained.apply('drop this')
        chained.apply('foo please')

        expect(chained.stats[:dropped]).to eq(1)
        expect(chained.stats[:passed]).to eq(1)
      end
    end

    describe 'combined structured and pattern rules' do
      it 'can combine drop_field with drop pattern rules' do
        filter.drop_field('debug_info').drop(/ERROR/)
        input = JSON.generate({ 'level' => 'info', 'debug_info' => 'verbose' })
        result = JSON.parse(filter.apply(input))
        expect(result).to eq({ 'level' => 'info' })
      end

      it 'can combine mask_field with replace rules' do
        filter.mask_field('ssn').replace(/token=\w+/, 'token=[REDACTED]')
        input = JSON.generate({ 'ssn' => '123-45-6789', 'msg' => 'token=abc123' })
        result = JSON.parse(filter.apply(input))
        expect(result['ssn']).to eq('***')
        expect(result['msg']).to eq('token=[REDACTED]')
      end
    end
  end

  describe Philiprehberger::LogFilter::Wrapper do
    let(:logger) { instance_double(Logger) }
    let(:filter) { Philiprehberger::LogFilter::Filter.new }
    let(:wrapper) { described_class.new(logger, filter) }

    describe 'log level delegation' do
      it 'delegates log calls through the filter' do
        allow(logger).to receive(:info)
        wrapper.info('hello world')
        expect(logger).to have_received(:info).with('hello world')
      end

      it 'skips logging when the filter drops the message' do
        filter.drop(/noisy/)
        allow(logger).to receive(:info)

        wrapper.info('noisy request')
        expect(logger).not_to have_received(:info)
      end
    end

    %i[debug info warn error fatal].each do |level|
      it "delegates #{level} calls" do
        allow(logger).to receive(level)
        wrapper.public_send(level, 'test message')
        expect(logger).to have_received(level).with('test message')
      end
    end

    describe 'block-based messages' do
      it 'evaluates block when no message is given' do
        allow(logger).to receive(:info)
        wrapper.info { 'lazy message' }
        expect(logger).to have_received(:info).with('lazy message')
      end

      it 'filters block-generated messages' do
        filter.drop(/noisy/)
        allow(logger).to receive(:info)
        wrapper.info { 'noisy log line' }
        expect(logger).not_to have_received(:info)
      end

      it 'skips logging when block returns nil' do
        allow(logger).to receive(:info)
        wrapper.info { nil }
        expect(logger).not_to have_received(:info)
      end
    end

    describe '#level' do
      it 'delegates level to underlying logger' do
        allow(logger).to receive(:level).and_return(1)
        expect(wrapper.level).to eq(1)
      end
    end

    describe '#level=' do
      it 'delegates level= to underlying logger' do
        allow(logger).to receive(:level=)
        wrapper.level = 2
        expect(logger).to have_received(:level=).with(2)
      end
    end

    describe '#close' do
      it 'delegates close to underlying logger' do
        allow(logger).to receive(:close)
        wrapper.close
        expect(logger).to have_received(:close)
      end
    end

    describe 'method_missing delegation' do
      it 'delegates unknown methods to the logger' do
        allow(logger).to receive(:respond_to?).with(:formatter, false).and_return(true)
        allow(logger).to receive(:respond_to?).with(:formatter).and_return(true)
        allow(logger).to receive(:formatter).and_return('my_formatter')
        expect(wrapper.formatter).to eq('my_formatter')
      end

      it 'raises NoMethodError for methods the logger does not support' do
        allow(logger).to receive(:respond_to?).and_return(false)
        expect { wrapper.nonexistent_method }.to raise_error(NoMethodError)
      end
    end

    describe 'message replacement through wrapper' do
      it 'applies replace rules before forwarding' do
        filter.replace(/token=\S+/, 'token=[REDACTED]')
        allow(logger).to receive(:warn)
        wrapper.warn('auth token=abc123 expired')
        expect(logger).to have_received(:warn).with('auth token=[REDACTED] expired')
      end
    end
  end

  describe Philiprehberger::LogFilter::Presets do
    describe '.health_check' do
      subject(:filter) { described_class.health_check }

      it 'drops health check paths' do
        expect(filter.apply('GET /health 200')).to be_nil
        expect(filter.apply('GET /ping 200')).to be_nil
        expect(filter.apply('GET /ready 200')).to be_nil
        expect(filter.apply('GET /alive 200')).to be_nil
        expect(filter.apply('healthcheck passed')).to be_nil
      end

      it 'passes normal requests' do
        expect(filter.apply('GET /api/users 200')).to eq('GET /api/users 200')
      end
    end

    describe '.assets' do
      subject(:filter) { described_class.assets }

      it 'drops asset requests' do
        expect(filter.apply('GET /app.css 200')).to be_nil
        expect(filter.apply('GET /bundle.js 200')).to be_nil
        expect(filter.apply('GET /logo.png 200')).to be_nil
        expect(filter.apply('GET /favicon.ico 200')).to be_nil
      end

      it 'passes non-asset requests' do
        expect(filter.apply('GET /api/data 200')).to eq('GET /api/data 200')
      end
    end

    describe '.bots' do
      subject(:filter) { described_class.bots }

      it 'drops bot user agents' do
        expect(filter.apply('Googlebot/2.1 crawling /page')).to be_nil
        expect(filter.apply('request from Bingbot')).to be_nil
        expect(filter.apply('spider scanning site')).to be_nil
      end

      it 'passes human requests' do
        expect(filter.apply('Mozilla/5.0 request')).to eq('Mozilla/5.0 request')
      end
    end

    describe '.pii' do
      subject(:filter) { described_class.pii }

      it 'redacts email addresses' do
        expect(filter.apply('login user=alice@example.com')).to eq('login user=[REDACTED]')
      end

      it 'redacts SSN-format numbers' do
        expect(filter.apply('SSN 123-45-6789 lookup')).to eq('SSN [REDACTED] lookup')
      end

      it 'redacts credit-card-shaped numbers' do
        expect(filter.apply('card 4242424242424242 charged')).to eq('card [REDACTED] charged')
      end

      it 'leaves a clean line untouched' do
        expect(filter.apply('GET /api/users 200')).to eq('GET /api/users 200')
      end
    end

    describe '.secrets' do
      subject(:filter) { described_class.secrets }

      it 'redacts Bearer tokens' do
        expect(filter.apply('Authorization: Bearer abc123.def456-_xyz')).to eq('Authorization: Bearer [REDACTED]')
      end

      it 'redacts api_key= parameters' do
        expect(filter.apply('GET /v1?api_key=sk_live_xyz123 200')).to eq('GET /v1?api_key=[REDACTED] 200')
      end

      it 'redacts AWS access keys' do
        expect(filter.apply('using AKIAIOSFODNN7EXAMPLE today')).to eq('using [REDACTED] today')
      end

      it 'leaves a clean line untouched' do
        expect(filter.apply('GET /healthz 200')).to eq('GET /healthz 200')
      end
    end
  end

  describe '.health_check_filter' do
    it 'returns a filter that drops health checks' do
      filter = described_class.health_check_filter
      expect(filter).to be_a(Philiprehberger::LogFilter::Filter)
      expect(filter.apply('GET /health 200')).to be_nil
    end
  end

  describe '.asset_filter' do
    it 'returns a filter that drops asset requests' do
      filter = described_class.asset_filter
      expect(filter).to be_a(Philiprehberger::LogFilter::Filter)
      expect(filter.apply('GET /style.css 200')).to be_nil
    end
  end

  describe '.bot_filter' do
    it 'returns a filter that drops bot requests' do
      filter = described_class.bot_filter
      expect(filter).to be_a(Philiprehberger::LogFilter::Filter)
      expect(filter.apply('Googlebot crawling')).to be_nil
    end
  end

  describe '.wrap' do
    it 'returns a Wrapper instance' do
      logger = instance_double(Logger)
      filter = Philiprehberger::LogFilter::Filter.new
      wrapper = described_class.wrap(logger, filter)
      expect(wrapper).to be_a(Philiprehberger::LogFilter::Wrapper)
    end
  end
end

RSpec.describe Philiprehberger::LogFilter::Filter, '#tap_each' do
  it 'invokes the block with every message that reaches the rule' do
    seen = []
    filter = described_class.new.tap_each { |msg| seen << msg }

    filter.apply('first')
    filter.apply('second')

    expect(seen).to eq(%w[first second])
  end

  it 'passes the message through unchanged regardless of block return value' do
    filter = described_class.new.tap_each { |_| 'ignored' }
    expect(filter.apply('hello')).to eq('hello')
  end

  it 'sees the transformed message when placed after a replace rule' do
    seen = []
    filter = described_class.new
                            .replace(/secret/, '[REDACTED]')
                            .tap_each { |msg| seen << msg }

    filter.apply('has secret data')

    expect(seen).to eq(['has [REDACTED] data'])
  end

  it 'does not run when an earlier rule drops the message' do
    seen = []
    filter = described_class.new
                            .drop(/DEBUG/)
                            .tap_each { |msg| seen << msg }

    filter.apply('DEBUG noise')

    expect(seen).to be_empty
  end

  it 'returns self for chaining' do
    filter = described_class.new
    expect(filter.tap_each { |_| nil }).to equal(filter)
  end
end

RSpec.describe Philiprehberger::LogFilter::Filter, '#describe_rules' do
  it 'returns an empty array for a new filter' do
    expect(described_class.new.describe_rules).to eq([])
  end

  it 'describes a chain of multiple rule types in order' do
    filter = described_class.new
                            .drop(/DEBUG/)
                            .replace(/password=\S+/, 'password=[REDACTED]')
                            .sample(/INFO/, rate: 0.25)
                            .mask_field('ssn')
                            .truncate(80, suffix: '...')

    descriptions = filter.describe_rules

    expect(descriptions.size).to eq(5)
    expect(descriptions[0]).to eq(type: :drop_pattern, description: 'drop matching /DEBUG/')
    expect(descriptions[1]).to eq(
      type: :replace,
      description: 'replace /password=\\S+/ with "password=[REDACTED]"'
    )
    expect(descriptions[2]).to eq(type: :sample, description: 'sample /INFO/ at rate 0.25')
    expect(descriptions[3]).to eq(type: :mask_field, description: 'mask field "ssn" with "***"')
    expect(descriptions[4]).to eq(
      type: :truncate,
      description: 'truncate to 80 chars with suffix "..."'
    )
  end

  it 'describes drop_if, drop_field, and tap rules' do
    filter = described_class.new
                            .drop_if { |_| false }
                            .drop_field('debug_info')
                            .tap_each { |_| nil }

    descriptions = filter.describe_rules

    expect(descriptions[0]).to eq(type: :drop_block, description: 'drop if block returns truthy')
    expect(descriptions[1]).to eq(type: :drop_field, description: 'drop field "debug_info"')
    expect(descriptions[2]).to eq(type: :tap, description: 'tap each message (side effect)')
  end
end

RSpec.describe Philiprehberger::LogFilter::Filter, '#explain' do
  it 'returns the transformed message and per-rule decisions when a message passes' do
    filter = described_class.new
                            .drop(/DEBUG/)
                            .replace(/password=\S+/, 'password=[REDACTED]')

    trace = filter.explain('user login password=abc123')

    expect(trace[:result]).to eq('user login password=[REDACTED]')
    expect(trace[:decisions]).to eq([
                                      { rule: 0, type: :drop_pattern, matched: false, action: :passed },
                                      { rule: 1, type: :replace,      matched: true,  action: :replaced }
                                    ])
  end

  it 'short-circuits at the rule that drops the message' do
    filter = described_class.new
                            .replace(/foo/, 'bar')
                            .drop(/bar/)
                            .replace(/never/, 'reached')

    trace = filter.explain('foo input')

    expect(trace[:result]).to be_nil
    expect(trace[:decisions].size).to eq(2)
    expect(trace[:decisions][0]).to eq(rule: 0, type: :replace,      matched: true, action: :replaced)
    expect(trace[:decisions][1]).to eq(rule: 1, type: :drop_pattern, matched: true, action: :dropped)
  end

  it 'reports :masked when mask_field key is present in JSON' do
    filter = described_class.new.mask_field('ssn', with: 'XXX')

    input = JSON.generate({ 'user' => 'alice', 'ssn' => '123-45-6789' })
    trace = filter.explain(input)

    expect(JSON.parse(trace[:result])).to eq({ 'user' => 'alice', 'ssn' => 'XXX' })
    expect(trace[:decisions]).to eq([
                                      { rule: 0, type: :mask_field, matched: true, action: :masked }
                                    ])
  end

  it 'reports :unchanged when mask_field key is absent in JSON' do
    filter = described_class.new.mask_field('ssn')

    input = JSON.generate({ 'user' => 'alice' })
    trace = filter.explain(input)

    expect(JSON.parse(trace[:result])).to eq({ 'user' => 'alice' })
    expect(trace[:decisions]).to eq([
                                      { rule: 0, type: :mask_field, matched: false, action: :unchanged }
                                    ])
  end

  it 'does not increment stats counters' do
    filter = described_class.new
                            .drop(/DEBUG/)
                            .replace(/secret/, '[REDACTED]')
                            .mask_field('ssn')

    stats_before = filter.stats

    filter.explain('DEBUG noisy line')
    filter.explain('has secret value')
    filter.explain('plain message')
    filter.explain(JSON.generate({ 'ssn' => '123-45-6789' }))

    expect(filter.stats).to eq(stats_before)
    expect(filter.stats).to eq({ dropped: 0, passed: 0, replaced: 0, sampled: 0 })
  end

  it 'does not invoke tap_each blocks' do
    tap_invocations = 0
    filter = described_class.new
                            .replace(/secret/, '[REDACTED]')
                            .tap_each { |_| tap_invocations += 1 }

    trace = filter.explain('has secret data')

    expect(tap_invocations).to eq(0)
    expect(trace[:result]).to eq('has [REDACTED] data')
    expect(trace[:decisions].last).to eq(rule: 1, type: :tap, matched: true, action: :tapped)
  end
end

RSpec.describe Philiprehberger::LogFilter::Presets, '.urls_only' do
  it 'keeps standard HTTP request-line entries' do
    filter = described_class.urls_only
    expect(filter.apply('GET /api/users 200')).to eq('GET /api/users 200')
    expect(filter.apply('POST /api/orders 201')).to eq('POST /api/orders 201')
    expect(filter.apply('DELETE /sessions/abc 204')).to eq('DELETE /sessions/abc 204')
  end

  it 'drops lines that are not request lines' do
    filter = described_class.urls_only
    expect(filter.apply('worker booted')).to be_nil
    expect(filter.apply('Some debug noise')).to be_nil
  end

  it 'drops verbs without a leading slash path' do
    expect(described_class.urls_only.apply('GET api/users 200')).to be_nil
  end
end
