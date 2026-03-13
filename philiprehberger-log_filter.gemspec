# frozen_string_literal: true

require_relative "lib/philiprehberger/log_filter/version"

Gem::Specification.new do |spec|
  spec.name          = "philiprehberger-log_filter"
  spec.version       = Philiprehberger::LogFilter::VERSION
  spec.authors       = ["Philip Rehberger"]
  spec.email         = ["me@philiprehberger.com"]

  spec.summary       = "Pattern-based log filtering with drop, replace, and preset rules"
  spec.description   = "Pattern-based log filtering — drop or transform log lines matching rules. " \
                       "Includes preset filters for health checks, static assets, and bot traffic."
  spec.homepage      = "https://github.com/philiprehberger/rb-log-filter"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"]        = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
end
