# frozen_string_literal: true

module Philiprehberger
  module LogFilter
    # Wraps a Ruby Logger (or any object responding to the standard log
    # level methods) and applies a {Filter} to every message before
    # forwarding.
    class Wrapper
      LOG_LEVELS = %i[debug info warn error fatal].freeze

      # @param logger [Logger] the underlying logger to delegate to
      # @param filter [Filter] the filter to apply to messages
      def initialize(logger, filter)
        @logger = logger
        @filter = filter
      end

      LOG_LEVELS.each do |level|
        # @param message [String, nil] the log message
        # @param args [Array] additional positional arguments
        # @return [void]
        define_method(level) do |message = nil, *args, &block|
          message = block&.call if message.nil? && block
          return if message.nil?

          filtered = @filter.apply(message.to_s)
          return if filtered.nil?

          @logger.public_send(level, filtered, *args)
        end
      end

      # @return [Integer] the current log level
      def level
        @logger.level
      end

      # @param new_level [Integer, Symbol] the new log level
      # @return [void]
      def level=(new_level)
        @logger.level = new_level
      end

      # Close the underlying logger.
      #
      # @return [void]
      def close
        @logger.close
      end

      # Delegate unknown methods to the underlying logger.
      def method_missing(method_name, ...)
        if @logger.respond_to?(method_name)
          @logger.public_send(method_name, ...)
        else
          super
        end
      end

      # @return [Boolean]
      def respond_to_missing?(method_name, include_private = false)
        @logger.respond_to?(method_name, include_private) || super
      end
    end
  end
end
