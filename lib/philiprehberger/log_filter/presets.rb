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
    end
  end
end
