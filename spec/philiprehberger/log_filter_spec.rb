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
end
