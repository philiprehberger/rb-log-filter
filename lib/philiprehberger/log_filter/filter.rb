# frozen_string_literal: true

require 'json'
require 'securerandom'

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
        @mutex = Mutex.new
        @stats = { dropped: 0, passed: 0, replaced: 0, sampled: 0 }
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

      # Add a sampling rule. Only pass through +rate+ fraction of messages
      # matching +pattern+. Non-matching messages pass through unaffected.
      #
      # @param pattern [Regexp] the pattern to match
      # @param rate [Float] sampling rate between 0.0 and 1.0
      # @return [self] for chaining
      def sample(pattern, rate:)
        raise ArgumentError, 'rate must be between 0.0 and 1.0' unless rate.is_a?(Numeric) && rate >= 0.0 && rate <= 1.0

        @rules << { type: :sample, pattern: pattern, rate: rate.to_f }
        self
      end

      # Add a rule to remove a field from JSON log messages.
      # Non-JSON messages pass through unmodified.
      #
      # @param key [String] the JSON field key to remove
      # @return [self] for chaining
      def drop_field(key)
        @rules << { type: :drop_field, key: key.to_s }
        self
      end

      # Add a rule to mask a field value in JSON log messages.
      # Non-JSON messages pass through unmodified.
      #
      # @param key [String] the JSON field key to mask
      # @param with [String] the mask replacement value
      # @return [self] for chaining
      def mask_field(key, with: '***')
        @rules << { type: :mask_field, key: key.to_s, mask: with }
        self
      end

      # Return current filter statistics.
      #
      # @return [Hash] counters for :dropped, :passed, :replaced, :sampled
      def stats
        @mutex.synchronize { @stats.dup }
      end

      # Reset all statistics counters to zero.
      #
      # @return [void]
      def reset_stats!
        @mutex.synchronize do
          @stats = { dropped: 0, passed: 0, replaced: 0, sampled: 0 }
        end
      end

      # Run all rules against +message+ in order.
      #
      # @param message [String] the log message to filter
      # @return [String, nil] the transformed message, or +nil+ if dropped
      def apply(message)
        result = message.dup

        @rules.each do |rule|
          result = apply_rule(rule, result)
          if result.nil?
            increment_stat(:dropped)
            return nil
          end
        end

        increment_stat(:passed)
        result
      end

      # Compose this filter with +other+ into a new filter.
      #
      # The returned filter's +apply+ runs +self.apply+ first and passes the
      # result through +other.apply+. If the first filter drops the message
      # (returns +nil+), the second filter is not invoked and the chained
      # apply returns +nil+. Composition is associative, so
      # +a.chain(b).chain(c)+ behaves transitively.
      #
      # The chained filter tracks its own +stats+ independently of the two
      # source filters; each source filter continues to track its own
      # counters when invoked.
      #
      # @param other [Filter] the filter to run after this one
      # @return [Filter] a new filter composing +self+ and +other+
      # @raise [ArgumentError] if +other+ is not a {Filter}
      def chain(other)
        raise ArgumentError, 'other must be a Philiprehberger::LogFilter::Filter' unless other.is_a?(Filter)

        ChainedFilter.new(self, other)
      end

      private

      # @param stat [Symbol] the stat key to increment
      # @return [void]
      def increment_stat(stat)
        @mutex.synchronize { @stats[stat] += 1 }
      end

      # @param rule [Hash] a single rule hash
      # @param message [String] the current message
      # @return [String, nil]
      def apply_rule(rule, message)
        case rule[:type]
        when :drop_pattern
          message.match?(rule[:pattern]) ? nil : message
        when :drop_block
          rule[:block].call(message) ? nil : message
        when :replace
          replaced = message.gsub(rule[:pattern], rule[:replacement])
          if replaced != message
            increment_stat(:replaced)
          end
          replaced
        when :sample
          apply_sample_rule(rule, message)
        when :drop_field
          apply_drop_field_rule(rule, message)
        when :mask_field
          apply_mask_field_rule(rule, message)
        end
      end

      # @param rule [Hash] a sample rule
      # @param message [String] the current message
      # @return [String, nil]
      def apply_sample_rule(rule, message)
        return message unless message.match?(rule[:pattern])

        return unless SecureRandom.rand < rule[:rate]

        increment_stat(:sampled)
        message
      end

      # @param rule [Hash] a drop_field rule
      # @param message [String] the current message
      # @return [String]
      def apply_drop_field_rule(rule, message)
        parsed = parse_json(message)
        return message unless parsed

        parsed.delete(rule[:key])
        JSON.generate(parsed)
      rescue StandardError
        message
      end

      # @param rule [Hash] a mask_field rule
      # @param message [String] the current message
      # @return [String]
      def apply_mask_field_rule(rule, message)
        parsed = parse_json(message)
        return message unless parsed

        if parsed.key?(rule[:key])
          parsed[rule[:key]] = rule[:mask]
          increment_stat(:replaced)
        end
        JSON.generate(parsed)
      rescue StandardError
        message
      end

      # Attempt to parse a string as JSON.
      #
      # @param str [String] the string to parse
      # @return [Hash, nil] parsed hash or nil if not valid JSON object
      def parse_json(str)
        result = JSON.parse(str)
        result.is_a?(Hash) ? result : nil
      rescue JSON::ParserError
        nil
      end
    end

    # A filter produced by {Filter#chain} that pipes events through two
    # source filters in order. Tracks its own stats independently of the
    # inputs. Short-circuits when the first filter drops the event.
    #
    # @api private
    class ChainedFilter < Filter
      # @param first [Filter] the filter to run first
      # @param second [Filter] the filter to run on +first+'s output
      def initialize(first, second)
        super()
        @first = first
        @second = second
      end

      # Run +first.apply+ then +second.apply+. If the first returns +nil+,
      # the second is skipped and +nil+ is returned.
      #
      # @param message [String] the log message to filter
      # @return [String, nil] the transformed message, or +nil+ if dropped
      def apply(message)
        intermediate = @first.apply(message)
        if intermediate.nil?
          increment_stat(:dropped)
          return nil
        end

        result = @second.apply(intermediate)
        if result.nil?
          increment_stat(:dropped)
          return nil
        end

        increment_stat(:passed)
        result
      end
    end
  end
end
