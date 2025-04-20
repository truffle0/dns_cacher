require_relative 'dns_cacher/dns'
require_relative 'dns_cacher/endpoint'
require_relative 'dns_cacher/cache'
require_relative 'dns_cacher/resolver'

require 'async'
require 'async/barrier'

require 'logger'

module DNSCacher
  class BasicServer
    attr_reader :endpoints, :cache, :fiber
    attr_accessor :nameservers, :logger

    def initialize(endpoints = [], logger = nil)
      raise ArgumentError.new "No endpoints provided" if endpoints.empty?

      @logger = logger.nil? ? Logger.new(nil) : logger

      @cache = Cache.new
      @nameservers = DNSCacher::parse_nameservers
      @nameservers.each do |addr|
        @logger.info "Using nameserver #{addr.ip_address}:#{addr.ip_port}"
      end

      @endpoints = endpoints.each_with_object([]) do |addr, arr|
        arr << Endpoint.new(addr)
        @logger.info("Endpoint bound to #{addr.ip_address}:#{addr.ip_port}")
      end

      @notifier = nil
      @fiber = nil
    end

    # if run within an async reactor will return, otherwise will wait
    # for the server to die
    def run
      raise "Server already running!" unless @fiber.nil? or @fiber.stopped?
      @fiber = Async do
        # tracks running endpoints
        barrier = Async::Barrier.new

        # Start up listening on all endpoints
        @endpoints.each do |endpoint|
          # Run each endpoint async, and use 'handle_query' below to process queries
          barrier.async do
            endpoint.run{|pack| handle_query(pack)}
          end

        end

        barrier.wait
      ensure
        barrier.stop
      end
    end

    def handle_query packet
      query = DNS::Message.decode packet

      # in theory the DNS protocol can handle multiple requests
      # but in practice they reject any request that does this
      raise EncodingError.new("Found #{query.question.length} questions in query, max allowed is 1") unless query.question.length == 1
      question = query.question[0]

      if not @cache.nil? and records = @cache.fetch(question.qname, question.qtype)
        @logger.debug{"Query for #{question.qname} (cache hit)"}

        query.answer = records
        reply = query.response!

        return reply.encode
      else
        packet = Resolver::general_query(query, @nameservers)
        @logger.debug{"Query for #{question.qname} (cache miss)"}

        reply = DNS::Message.decode packet
        @cache.store(question.qname, question.qtype, reply.answer + reply.authority) unless @cache.nil?
        return packet
      end

    rescue EncodingError => e
      # Indicates packet encoding was invalid (or server is lacking some feature potentially)
      @logger.debug "Received invalid query: #{e.detailed_message}"
      return query.fail_format!.encode
    rescue IOError => e
      # indicates an issue with query forwarding, either not response or no nameservers available
      @logger.debug "Query for #{question.qname} failed: #{e.message}"
      return query.fail_server!.encode
    rescue Exception => e
      @logger.error("Internal server error:\n#{e.full_message}")
      return query.fail_server!.encode
    end

    # pass on call to await main server task
    def wait
      @fiber.wait unless @fiber.nil?
    end

    def stop
      # Stop notifier
      @notifier.exit.join
      @notifier = nil

      # stop the main fiber to bring down all endpoints
      # and currently running tasks
      @fiber.stop
    end
  end
end
