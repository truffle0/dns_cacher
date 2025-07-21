# frozen_string_literal: true

require_relative "lib/dns_cacher/version"

Gem::Specification.new do |spec|
  spec.name = "dns_cacher"
  spec.version = DNSCacher::VERSION
  spec.authors = ["truffle"]
  spec.email = ["truffle@b0tt0m.xyz"]

  spec.summary = "A minimal and lightweight local DNS/mDNS caching server"
  spec.homepage = "https://git.b0tt0m.xyz/truffle/dns_cacher"
  spec.license = "GPL-3.0"
  spec.required_ruby_version = ">= 3.0.0"
  
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  #spec.metadata["changelog_uri"] =

  gemspec = File.basename(__FILE__)
  spec.files = Dir.glob("lib/**/*.rb") + Dir.glob("exe/*")
  spec.bindir = "exe"
  spec.executables = spec.files.grep(/^exe\//) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "async", "~> 2.8"
end
