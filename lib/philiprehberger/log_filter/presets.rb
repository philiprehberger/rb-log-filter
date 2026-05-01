# frozen_string_literal: true

module Philiprehberger
  module LogFilter
    # Factory methods that return pre-configured {Filter} instances for
    # common log-noise scenarios.
    module Presets
      # Filter that drops health-check request log lines.
      #
      # @return [Filter] a filter suppressing health-check paths
      def self.health_check
        Filter.new.drop(%r{health_?check|/health|/ping|/ready|/alive}i)
      end

      # Filter that drops static-asset request log lines.
      #
      # @return [Filter] a filter suppressing asset paths
      def self.assets
        Filter.new.drop(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)\b/i)
      end

      # Filter that drops bot/crawler request log lines.
      #
      # @return [Filter] a filter suppressing bot user-agents
      def self.bots
        Filter.new.drop(/bot|crawler|spider|slurp|googlebot|bingbot/i)
      end

      # Filter that redacts common PII patterns from log lines.
      #
      # Replaces email addresses, US Social Security Numbers, and 13–19 digit
      # credit-card-shaped numbers with `[REDACTED]`.
      #
      # @return [Filter] a filter replacing PII with `[REDACTED]`
      def self.pii
        Filter.new
              .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i, '[REDACTED]')
              .replace(/\b\d{3}-\d{2}-\d{4}\b/, '[REDACTED]')
              .replace(/\b\d(?:[ -]?\d){12,18}\b/, '[REDACTED]')
      end

      # Filter that redacts common secret patterns from log lines.
      #
      # Replaces Bearer tokens, `api_key=...`/`api-key=...` values, and
      # AWS-style access key IDs with `[REDACTED]`.
      #
      # @return [Filter] a filter replacing secrets with `[REDACTED]`
      def self.secrets
        Filter.new
              .replace(/Bearer\s+[A-Za-z0-9._-]+/, 'Bearer [REDACTED]')
              .replace(/\b(api[_-]?key|access[_-]?token)=([A-Za-z0-9._-]+)/i, '\1=[REDACTED]')
              .replace(/\bAKIA[0-9A-Z]{16}\b/, '[REDACTED]')
      end
    end
  end
end
