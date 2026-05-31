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

      # Add a side-effecting inspection rule. The block is called with every
      # message that reaches this stage of the pipeline (after any previous
      # transforms applied). The message is then passed through unchanged —
      # the block's return value is ignored. Exceptions raised inside the
      # block are not swallowed.
      #
      # Useful for counting, metrics emission, or attaching to a debugger
      # without altering the filter output.
      #
      # @yield [message] receives the current message
      # @yieldparam message [String]
      # @return [self] for chaining
      def tap_each(&block)
        @rules << { type: :tap, block: block }
        self
      end

      # Add a rule that caps outgoing messages at +max_length+ characters,
      # appending +suffix+ when truncation occurred. Messages shorter than
      # or equal to +max_length+ pass through unchanged. Never drops a
      # message, only transforms it.
      #
      # @param max_length [Integer] the maximum length of the message in characters
      # @param suffix [String] the string appended when truncation occurs
      # @return [self] for chaining
      # @raise [ArgumentError] if +max_length+ is not a positive Integer
      def truncate(max_length, suffix: '…')
        raise ArgumentError, 'max_length must be a positive Integer' unless max_length.is_a?(Integer) && max_length.positive?

        @rules << { type: :truncate, max_length: max_length, suffix: suffix }
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

      # Return a human-readable description of every rule in the chain,
      # in declaration order. Useful for debugging, logging, or rendering
      # the filter configuration in an admin UI.
      #
      # Does not mutate any state and does not invoke any rule blocks.
      #
      # @return [Array<Hash{Symbol=>Object}>] one hash per rule with
      #   +:type+ (the rule's symbol type) and +:description+ (a
      #   human-readable string)
      def describe_rules
        @rules.map { |r| { type: r[:type], description: describe_rule(r) } }
      end

      # Run +message+ through the chain WITHOUT mutating stats and WITHOUT
      # invoking any +tap_each+ blocks. Returns a trace describing what
      # each rule did to the message, plus the final transformed value
      # (or +nil+ if the chain would have dropped it).
      #
      # Intended for debugging filter configurations. Because +:sample+
      # rules are stochastic, this method treats a sample rule as a
      # deterministic +sampled_in+ when its pattern matches (it shows the
      # path the message would take if the sample passed). This makes
      # +explain+ deterministic and side-effect-free.
      #
      # @param message [String] the log message to trace
      # @return [Hash] with +:result+ (the transformed message or +nil+)
      #   and +:decisions+ (an array of per-rule decision hashes). Each
      #   decision hash has +:rule+ (0-indexed integer), +:type+ (the
      #   rule's symbol), +:matched+ (whether the rule applied), and
      #   +:action+ (one of +:passed+, +:dropped+, +:replaced+, +:masked+,
      #   +:sampled_in+, +:sampled_out+, +:truncated+, +:tapped+,
      #   +:unchanged+).
      def explain(message)
        decisions = []
        result = message.dup

        @rules.each_with_index do |rule, idx|
          decision, new_result = explain_rule(rule, result, idx)
          decisions << decision
          if decision[:action] == :dropped
            return { result: nil, decisions: decisions }
          end

          result = new_result
        end

        { result: result, decisions: decisions }
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
        when :truncate
          apply_truncate_rule(rule, message)
        when :tap
          rule[:block].call(message)
          message
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

      # @param rule [Hash] a truncate rule
      # @param message [String] the current message
      # @return [String]
      def apply_truncate_rule(rule, message)
        return message if message.length <= rule[:max_length]

        suffix = rule[:suffix]
        max_length = rule[:max_length]

        return suffix[0, max_length] if suffix.length >= max_length

        message[0, max_length - suffix.length] + suffix
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

      # Render a single rule as a human-readable string.
      #
      # @param rule [Hash] a single rule hash
      # @return [String]
      def describe_rule(rule)
        case rule[:type]
        when :drop_pattern
          "drop matching #{rule[:pattern].inspect}"
        when :drop_block
          'drop if block returns truthy'
        when :replace
          "replace #{rule[:pattern].inspect} with #{rule[:replacement].inspect}"
        when :sample
          "sample #{rule[:pattern].inspect} at rate #{rule[:rate]}"
        when :drop_field
          "drop field #{rule[:key].inspect}"
        when :mask_field
          "mask field #{rule[:key].inspect} with #{rule[:mask].inspect}"
        when :truncate
          "truncate to #{rule[:max_length]} chars with suffix #{rule[:suffix].inspect}"
        when :tap
          'tap each message (side effect)'
        end
      end

      # Trace a single rule for {#explain}. Returns a [decision, new_message]
      # pair. Never mutates stats and never calls user-supplied tap blocks.
      #
      # @param rule [Hash] a single rule hash
      # @param message [String] the current message
      # @param idx [Integer] the 0-based index of the rule in the chain
      # @return [Array(Hash, String)]
      def explain_rule(rule, message, idx)
        case rule[:type]
        when :drop_pattern
          if message.match?(rule[:pattern])
            [{ rule: idx, type: rule[:type], matched: true, action: :dropped }, message]
          else
            [{ rule: idx, type: rule[:type], matched: false, action: :passed }, message]
          end
        when :drop_block
          if rule[:block].call(message)
            [{ rule: idx, type: rule[:type], matched: true, action: :dropped }, message]
          else
            [{ rule: idx, type: rule[:type], matched: false, action: :passed }, message]
          end
        when :replace
          replaced = message.gsub(rule[:pattern], rule[:replacement])
          if replaced == message
            [{ rule: idx, type: rule[:type], matched: false, action: :unchanged }, message]
          else
            [{ rule: idx, type: rule[:type], matched: true, action: :replaced }, replaced]
          end
        when :sample
          if message.match?(rule[:pattern])
            [{ rule: idx, type: rule[:type], matched: true, action: :sampled_in }, message]
          else
            [{ rule: idx, type: rule[:type], matched: false, action: :unchanged }, message]
          end
        when :drop_field
          parsed = parse_json(message)
          if parsed&.key?(rule[:key])
            parsed.delete(rule[:key])
            [{ rule: idx, type: rule[:type], matched: true, action: :replaced },
             JSON.generate(parsed)]
          else
            [{ rule: idx, type: rule[:type], matched: false, action: :unchanged }, message]
          end
        when :mask_field
          parsed = parse_json(message)
          if parsed&.key?(rule[:key])
            parsed[rule[:key]] = rule[:mask]
            [{ rule: idx, type: rule[:type], matched: true, action: :masked },
             JSON.generate(parsed)]
          else
            [{ rule: idx, type: rule[:type], matched: false, action: :unchanged }, message]
          end
        when :truncate
          if message.length > rule[:max_length]
            suffix = rule[:suffix]
            max_length = rule[:max_length]
            new_msg = if suffix.length >= max_length
                        suffix[0, max_length]
                      else
                        message[0, max_length - suffix.length] + suffix
                      end
            [{ rule: idx, type: rule[:type], matched: true, action: :truncated }, new_msg]
          else
            [{ rule: idx, type: rule[:type], matched: false, action: :unchanged }, message]
          end
        when :tap
          # Intentionally do not invoke the tap block — explain is side-effect-free.
          [{ rule: idx, type: rule[:type], matched: true, action: :tapped }, message]
        end
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
