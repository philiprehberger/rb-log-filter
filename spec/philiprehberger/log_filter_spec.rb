# frozen_string_literal: true

require "spec_helper"
require "logger"

RSpec.describe Philiprehberger::LogFilter do
  it "has a version number" do
    expect(Philiprehberger::LogFilter::VERSION).not_to be_nil
  end

  describe Philiprehberger::LogFilter::Filter do
    subject(:filter) { described_class.new }

    describe "#drop" do
      it "suppresses messages matching the pattern" do
        filter.drop(/secret/)
        expect(filter.apply("this is secret data")).to be_nil
      end

      it "passes messages that do not match" do
        filter.drop(/secret/)
        expect(filter.apply("this is public data")).to eq("this is public data")
      end
    end

    describe "#drop_if" do
      it "suppresses messages when the block returns true" do
        filter.drop_if { |msg| msg.length > 10 }
        expect(filter.apply("a long message here")).to be_nil
      end

      it "passes messages when the block returns false" do
        filter.drop_if { |msg| msg.length > 100 }
        expect(filter.apply("short")).to eq("short")
      end
    end

    describe "#replace" do
      it "transforms content matching the pattern" do
        filter.replace(/password=\S+/, "password=[REDACTED]")
        expect(filter.apply("user login password=abc123")).to eq("user login password=[REDACTED]")
      end
    end

    describe "#apply" do
      it "chains multiple rules in order" do
        filter.drop(/debug/).replace(/secret/, "[REDACTED]")

        expect(filter.apply("debug info")).to be_nil
        expect(filter.apply("has secret value")).to eq("has [REDACTED] value")
        expect(filter.apply("normal message")).to eq("normal message")
      end
    end

    describe "chaining syntax" do
      it "supports fluent chaining" do
        result = described_class.new
                                .drop(/foo/)
                                .drop(/bar/)
                                .replace(/secret/, "[REDACTED]")

        expect(result).to be_a(described_class)
        expect(result.apply("foo")).to be_nil
        expect(result.apply("bar")).to be_nil
        expect(result.apply("my secret plan")).to eq("my [REDACTED] plan")
        expect(result.apply("hello")).to eq("hello")
      end
    end

    # --- Expanded tests ---

    describe "#rules" do
      it "returns an empty array for a new filter" do
        expect(filter.rules).to eq([])
      end

      it "accumulates rules in order" do
        filter.drop(/a/).replace(/b/, "c").drop_if { |_| false }
        expect(filter.rules.size).to eq(3)
        expect(filter.rules[0][:type]).to eq(:drop_pattern)
        expect(filter.rules[1][:type]).to eq(:replace)
        expect(filter.rules[2][:type]).to eq(:drop_block)
      end
    end

    describe "drop rule ordering matters" do
      it "applies replace before drop when replace is first" do
        filter.replace(/secret/, "open").drop(/open/)
        expect(filter.apply("this is secret")).to be_nil
      end

      it "drops before replace when drop is first" do
        filter.drop(/secret/).replace(/open/, "closed")
        expect(filter.apply("this is secret")).to be_nil
      end
    end

    describe "empty message" do
      it "returns empty string for empty input" do
        filter.drop(/something/)
        expect(filter.apply("")).to eq("")
      end
    end

    describe "multiple replacements in one message" do
      it "replaces all occurrences of the pattern" do
        filter.replace(/\d+/, "NUM")
        expect(filter.apply("order 123 item 456")).to eq("order NUM item NUM")
      end
    end

    describe "drop_if with complex logic" do
      it "can use multi-condition logic in block" do
        filter.drop_if { |msg| msg.include?("error") && msg.include?("timeout") }
        expect(filter.apply("error: timeout occurred")).to be_nil
        expect(filter.apply("error: bad input")).to eq("error: bad input")
        expect(filter.apply("timeout warning")).to eq("timeout warning")
      end
    end

    describe "no rules applied" do
      it "returns message unchanged when no rules exist" do
        expect(filter.apply("any message")).to eq("any message")
      end
    end

    describe "case-insensitive patterns" do
      it "supports case-insensitive regex" do
        filter.drop(/SECRET/i)
        expect(filter.apply("this is Secret data")).to be_nil
        expect(filter.apply("this is secret data")).to be_nil
      end
    end
  end

  describe Philiprehberger::LogFilter::Wrapper do
    let(:logger) { instance_double(Logger) }
    let(:filter) { Philiprehberger::LogFilter::Filter.new }
    let(:wrapper) { described_class.new(logger, filter) }

    describe "log level delegation" do
      it "delegates log calls through the filter" do
        allow(logger).to receive(:info)
        wrapper.info("hello world")
        expect(logger).to have_received(:info).with("hello world")
      end

      it "skips logging when the filter drops the message" do
        filter.drop(/noisy/)
        allow(logger).to receive(:info)

        wrapper.info("noisy request")
        expect(logger).not_to have_received(:info)
      end
    end

    %i[debug info warn error fatal].each do |level|
      it "delegates #{level} calls" do
        allow(logger).to receive(level)
        wrapper.public_send(level, "test message")
        expect(logger).to have_received(level).with("test message")
      end
    end

    # --- Expanded tests ---

    describe "block-based messages" do
      it "evaluates block when no message is given" do
        allow(logger).to receive(:info)
        wrapper.info { "lazy message" }
        expect(logger).to have_received(:info).with("lazy message")
      end

      it "filters block-generated messages" do
        filter.drop(/noisy/)
        allow(logger).to receive(:info)
        wrapper.info { "noisy log line" }
        expect(logger).not_to have_received(:info)
      end

      it "skips logging when block returns nil" do
        allow(logger).to receive(:info)
        wrapper.info { nil }
        expect(logger).not_to have_received(:info)
      end
    end

    describe "#level" do
      it "delegates level to underlying logger" do
        allow(logger).to receive(:level).and_return(1)
        expect(wrapper.level).to eq(1)
      end
    end

    describe "#level=" do
      it "delegates level= to underlying logger" do
        allow(logger).to receive(:level=)
        wrapper.level = 2
        expect(logger).to have_received(:level=).with(2)
      end
    end

    describe "#close" do
      it "delegates close to underlying logger" do
        allow(logger).to receive(:close)
        wrapper.close
        expect(logger).to have_received(:close)
      end
    end

    describe "method_missing delegation" do
      it "delegates unknown methods to the logger" do
        allow(logger).to receive(:respond_to?).with(:formatter, false).and_return(true)
        allow(logger).to receive(:respond_to?).with(:formatter).and_return(true)
        allow(logger).to receive(:formatter).and_return("my_formatter")
        expect(wrapper.formatter).to eq("my_formatter")
      end

      it "raises NoMethodError for methods the logger does not support" do
        allow(logger).to receive(:respond_to?).and_return(false)
        expect { wrapper.nonexistent_method }.to raise_error(NoMethodError)
      end
    end

    describe "message replacement through wrapper" do
      it "applies replace rules before forwarding" do
        filter.replace(/token=\S+/, "token=[REDACTED]")
        allow(logger).to receive(:warn)
        wrapper.warn("auth token=abc123 expired")
        expect(logger).to have_received(:warn).with("auth token=[REDACTED] expired")
      end
    end
  end

  describe Philiprehberger::LogFilter::Presets do
    describe ".health_check" do
      subject(:filter) { described_class.health_check }

      it "drops health check paths" do
        expect(filter.apply("GET /health 200")).to be_nil
        expect(filter.apply("GET /ping 200")).to be_nil
        expect(filter.apply("GET /ready 200")).to be_nil
        expect(filter.apply("GET /alive 200")).to be_nil
        expect(filter.apply("healthcheck passed")).to be_nil
      end

      it "passes normal requests" do
        expect(filter.apply("GET /api/users 200")).to eq("GET /api/users 200")
      end
    end

    describe ".assets" do
      subject(:filter) { described_class.assets }

      it "drops asset requests" do
        expect(filter.apply("GET /app.css 200")).to be_nil
        expect(filter.apply("GET /bundle.js 200")).to be_nil
        expect(filter.apply("GET /logo.png 200")).to be_nil
        expect(filter.apply("GET /favicon.ico 200")).to be_nil
      end

      it "passes non-asset requests" do
        expect(filter.apply("GET /api/data 200")).to eq("GET /api/data 200")
      end
    end

    describe ".bots" do
      subject(:filter) { described_class.bots }

      it "drops bot user agents" do
        expect(filter.apply("Googlebot/2.1 crawling /page")).to be_nil
        expect(filter.apply("request from Bingbot")).to be_nil
        expect(filter.apply("spider scanning site")).to be_nil
      end

      it "passes human requests" do
        expect(filter.apply("Mozilla/5.0 request")).to eq("Mozilla/5.0 request")
      end
    end
  end

  # --- Expanded module-level tests ---

  describe ".health_check_filter" do
    it "returns a filter that drops health checks" do
      filter = described_class.health_check_filter
      expect(filter).to be_a(Philiprehberger::LogFilter::Filter)
      expect(filter.apply("GET /health 200")).to be_nil
    end
  end

  describe ".asset_filter" do
    it "returns a filter that drops asset requests" do
      filter = described_class.asset_filter
      expect(filter).to be_a(Philiprehberger::LogFilter::Filter)
      expect(filter.apply("GET /style.css 200")).to be_nil
    end
  end

  describe ".bot_filter" do
    it "returns a filter that drops bot requests" do
      filter = described_class.bot_filter
      expect(filter).to be_a(Philiprehberger::LogFilter::Filter)
      expect(filter.apply("Googlebot crawling")).to be_nil
    end
  end

  describe ".wrap" do
    it "returns a Wrapper instance" do
      logger = instance_double(Logger)
      filter = Philiprehberger::LogFilter::Filter.new
      wrapper = described_class.wrap(logger, filter)
      expect(wrapper).to be_a(Philiprehberger::LogFilter::Wrapper)
    end
  end
end
