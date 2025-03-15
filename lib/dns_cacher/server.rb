require 'socket'
require 'logger'
require 'async'

require_relative 'dns'
require_relative 'cache'

module Server
  MDNS_DOMAINS = [ "local" ]
  PATIENCE = 2

  LOGGER = Logger.new nil

  NAMESERVERS = []
  def self.update_nameservers!(source = "/etc/resolv.conf")
    NAMESERVERS.clear

    File.open(source).each_line do |line|
      md = /^nameserver\s+(?'addr'.*)(\s*#.*)?/.match(line)

      # we're only interested in nameservers
      next if md.nil?

      # skip loopback addresses (that's this server)
      addr = Addrinfo.udp(md[:addr], 53)
      next if addr.ipv4_loopback? or addr.ipv6_loopback?

      NAMESERVERS << addr
      LOGGER.info "Using nameserver #{md[:addr]}"
    end
  end

  module Resolver
    # Query the system nameservers
    #
    # This is done directly instead of through the Resolv
    # class to reuse existing encoding, and to allow
    # later expansion to support more advanced protocols like DNSSEC
    #
    # (Personally, I also just wanted to learn about the DNS protocol)
    def self.dns(query, nameservers)
      # Create a new socket for the outbound connection, and bind to an available port
      s = Socket.new :INET, :DGRAM, 0
      s.bind Addrinfo.udp('0.0.0.0', 0)

      # forward query onto each available nameserver in turn
      # until we get a response
      packet = query.encode
      reply, responder = nameservers.each do |server|
        s.sendmsg packet, 0, server

        begin
          reply, responder = s.recvmsg_nonblock
          break reply, responder
        rescue IO::WaitReadable
          read, = IO.select([s], nil, nil, PATIENCE)
          retry unless read.nil? # indicates timeout rather than available IO
        end
      end

      raise IOError.new "No one responded to query" if reply.nil?

      unless responder.ip_address == nameservers[0].ip_address
        LOGGER.warn "Nameserver '#{nameservers[0].ip_address}' was queried, but '#{responder.ip_address}' responded!"
      end

      return reply
    end

    def self.mdns(query)
      s = Socket.new :INET, :DGRAM, 0
      s.bind Addrinfo.udp("0.0.0.0", 0)

      s.sendmsg query.encode, 0, Addrinfo.udp("224.0.0.251", 5353) # Standard mDNS multicast address

      begin
        reply, responder = s.recvmsg_nonblock
      rescue IO::WaitReadable
        read, = IO.select([s], nil, nil, PATIENCE)
        retry unless read.nil?
        raise IOError "No one responded to query for #{query.question[0].qname}"
      end

     return reply
    end
  end

  class Endpoint
    attr_reader :addr, :family
    attr_accessor :cache, :nameservers

    def initialize(addr, cache=nil, nameservers=NAMESERVERS)
      @addr = addr
      @family = addr.ipv4? ? :INET : :INET6

      @socket = Socket.new @family, :DGRAM, 0
      @socket.bind addr

      # Set the cache and nameservers list for the server to query
      @cache = cache
      @nameservers = nameservers
    end

    def run
      loop do
        query, client, = @socket.recvmsg

        # Spawn a fibre to handle the query
        # to remove wait time
        Async do
          resolve_query(query, client)
        end
      end
    end

    def forward_query query
      domain = query.question[0].qname
      if domain.end_with? "local"
        Resolver.mdns(query)
      else
        Resolver.dns(query, @nameservers)
      end
    end

    def resolve_query packet, client
      query = DNS::Message.decode packet

      # in theory the DNS protocol can handle multiple requests
      # but in practice they reject any request that does this
      raise EncodingError unless query.question.length == 1
      question = query.question[0]

      if not @cache.nil? and records = @cache.fetch(question.qname, question.qtype)
        LOGGER.debug{"Query from #{client.ip_address}:#{client.ip_port} - #{question.qname} #{question.qtype} (cache hit)"}
        query.answer = records
        reply = query.response!

        @socket.sendmsg reply.encode, 0, client
      else
        LOGGER.debug{"Query from #{client.ip_address}:#{client.ip_port} - #{question.qname} #{question.qtype} (cache miss)"}
        packet = forward_query query
        @socket.sendmsg packet, 0, client

        reply = DNS::Message.decode packet
        @cache.store(question.qname, question.qtype, reply.answer + reply.authority) unless @cache.nil?
      end

    rescue EncodingError
      @socket.sendmsg query.fail_format!.encode, 0, client
    rescue Exception => e
      @socket.sendmsg query.fail_server!.encode, 0, client
      LOGGER.error "Internal server failure!"
      raise e
    end

    def finalize obj_id
      @socket.close
    end
  end
end
