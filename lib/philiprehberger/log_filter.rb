# frozen_string_literal: true

require_relative "log_filter/version"
require_relative "log_filter/filter"
require_relative "log_filter/wrapper"
require_relative "log_filter/presets"

module Philiprehberger
  module LogFilter
    class Error < StandardError; end

    def self.health_check_filter
      Presets.health_check
    end

    def self.asset_filter
      Presets.assets
    end

    def self.bot_filter
      Presets.bots
    end

    def self.wrap(logger, filter)
      Wrapper.new(logger, filter)
    end
  end
end
