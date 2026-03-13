# frozen_string_literal: true

module Philiprehberger
  module LogFilter
    # Chain of rules that can drop or transform log messages.
    #
    # Rules are evaluated in the order they were added. A drop rule
    # short-circuits and returns +nil+. A replace rule mutates the
    # message string before passing it to the next rule.
    class Filter
      # @return [Array<Hash>] the ordered list of rules
      attr_reader :rules

      def initialize
        @rules = []
      end

      # Add a pattern-based drop rule. Messages matching +pattern+ are suppressed.
      #
      # @param pattern [Regexp] the pattern to match against
      # @return [self] for chaining
      def drop(pattern)
        @rules << { type: :drop_pattern, pattern: pattern }
        self
      end

      # Add a block-based drop rule. Messages for which the block returns
      # a truthy value are suppressed.
      #
      # @yield [message] evaluates whether the message should be dropped
      # @yieldparam message [String]
      # @yieldreturn [Boolean]
      # @return [self] for chaining
      def drop_if(&block)
        @rules << { type: :drop_block, block: block }
        self
      end

      # Add a replacement rule. Occurrences of +pattern+ in the message
      # are replaced with +replacement+.
      #
      # @param pattern [Regexp] the pattern to match
      # @param replacement [String] the replacement string
      # @return [self] for chaining
      def replace(pattern, replacement)
        @rules << { type: :replace, pattern: pattern, replacement: replacement }
        self
      end

      # Run all rules against +message+ in order.
      #
      # @param message [String] the log message to filter
      # @return [String, nil] the transformed message, or +nil+ if dropped
      def apply(message)
        result = message.dup

        @rules.each do |rule|
          result = apply_rule(rule, result)
          return nil if result.nil?
        end

        result
      end

      private

      # @param rule [Hash] a single rule hash
      # @param message [String] the current message
      # @return [String, nil]
      def apply_rule(rule, message)
        case rule[:type]
        when :drop_pattern then message.match?(rule[:pattern]) ? nil : message
        when :drop_block   then rule[:block].call(message) ? nil : message
        when :replace      then message.gsub(rule[:pattern], rule[:replacement])
        end
      end
    end
  end
end
