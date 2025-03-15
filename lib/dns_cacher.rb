require_relative 'dns_cacher/dns'
require_relative 'dns_cacher/endpoint'
require_relative 'dns_cacher/cache'
require_relative 'dns_cacher/resolver'

require 'async'
require 'async/barrier'

require 'rb-inotify'
require 'logger'

module DNSCacher
  DEFAULT_ENDPOINTS = [ Addrinfo.udp("127.0.0.1", 53), Addrinfo.udp("::1", 53) ]

  attr_reader :logger, :endpoints, :cache
  attr_accessor :nameservers

  class BasicServer
    def initialize(endpoints = DEFAULT_ENDPOINTS, debug = false)
      @logger = Logger.new STDOUT
      @logger.level = debug ? Logger::DEBUG : Logger::INFO

      @cache = Cache.new
      @nameservers = DNSCacher::parse_nameservers
      @nameservers.each do |addr|
        @logger.info "Using nameserver #{addr.ip_address}:#{addr.ip_port}"
      end

      @endpoints = endpoints.each_with_object([]) do |addr, arr|
        arr << Endpoint.new(addr)
      end

      # Set a barrier to track running endpoints
      # allows server to be awaited or sync'd
      @barrier = Async::Barrier.new
      @notifier = nil
    end

    # if run within an async reactor will return, otherwise will wait
    # for the server to die
    def run
      Sync do
        unless @notifier.nil? and @barrier.empty?
          raise "Attempting to start server multiple times!"
        end

        # Start up listener for nameserver updates
        # currently a Thread (not async) has to be used as inotify-rb hangs the async reactor :(
        # TODO: implement using async rather than separate thread if possible
        @notifier = Thread.new do
          @logger.info("Started INotify listener for /etc/resolv.conf")
          notifier = INotify::Notifier.new
          notifier.watch("/etc/resolv.conf", :modify) do |event|
            @logger.debug "Detected change to /etc/resolv.conf"

            # WARN: this is not a sync'd opeartion, it shouldn't have the potential
            # to do (much?) damage based on how @nameservers isused, but should be fixed anyway
            @nameservers = DNSCacher.update_nameservers
          end
        end

        # Start up listening on all endpoints
        @endpoints.each do |endpoint|
          # Run each endpoint async
          @barrier.async do
            endpoint.run{|pack| handle_query(pack)}
          end

          @logger.info("Endpoint listening on #{endpoint.addr.ip_address}:#{endpoint.addr.ip_port}")
        end
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
        @logger.debug{"Query for #{question.qname} (cache miss)"}
        packet = Resolver::general_query(query, @nameservers)

        reply = DNS::Message.decode packet
        @cache.store(question.qname, question.qtype, reply.answer + reply.authority) unless @cache.nil?
        return packet
      end

    rescue EncodingError => e
      @logger.debug "Received invalid query: #{e.detailed_message}"
      return query.fail_format!.encode
    rescue Exception => e
      @logger.error("Internal server error:\n#{e.full_message}")
      return query.fail_server!.encode
    end

    # blocks until all endpoints have died
    def await
      @barrier.wait
    end

    def stop
      # Stop notifier
      @notifier.exit.join
      @notifier = nil

      # Stop all running endpoints
      @barrier.stop
    end
  end
end
