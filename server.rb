#!/bin/env ruby

require 'socket'
require 'logger'
require 'async'

require_relative 'dns'

$ENDPOINTS = [
  Addrinfo.udp('127.0.0.1', 53),
  Addrinfo.udp('::1', 53),
]
$MDNS_DOMAINS = [ "local" ]
$NAMESERVERS = [ Addrinfo.udp('8.8.8.8', 53) ]

$PATIENCE = 2

$logger = Logger.new STDOUT

# Cache responses from DNS queries
# automatically purges once TTL has expired
class Cache
  CacheKey = Struct.new(:domain, :rcode)

  def initialize
    @cache = {}
  end

  def store(domain, rcode, records)
    ttl = records.map{|x| x.ttl}.min
    key = CacheKey.new(domain, rcode)
    
    if ttl.nil? or ttl == 0
      $logger.debug "Not caching #{domain} #{rcode} as ttl is 0"
      return records
    end

    @cache[key] = records

    Async do
      sleep ttl
      $logger.debug "Purging #{key.domain} from cache after #{ttl}s"
      @cache.delete key
    end

    return records
  end

  def fetch(domain, rcode)
    @cache.fetch(CacheKey.new(domain, rcode), nil)
  end

end

$CACHE = Cache.new

# Extension to the DNS::Message class
# adds functions that convert messages (in-place)
# to predefined formats
class DNS::Message
  def fail_format!
    self.qr = true
    self.ra = true
    self.rcode = 1

    self.authority.clear()
    self.additional.clear()

    return self
  end

  # Formats message into
  def fail_server!
    self.qr = true
    self.ra = self.aa = true
    self.rcode = 2

    self.authority.clear()
    self.additional.clear()
    
    return self
  end

  # Formats message into a standard (successful) response
  def response!
    self.qr = true
    self.ra = self.aa = true
    self.rcode = 0

    self.authority.clear()
    self.additional.clear()

    return self
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
  def self.dns query
    # Create a new socket for the outbound connection, and bind to an available port
    s = Socket.new :INET, :DGRAM, 0
    s.bind Addrinfo.udp('0.0.0.0', 0)

    # forward query onto each available nameserver in turn
    # until we get a response
    packet = query.encode
    reply, responder = $NAMESERVERS.each do |server|
      s.sendmsg packet, 0, server

      begin
        reply, responder = s.recvmsg_nonblock
        break reply, responder
      rescue IO::WaitReadable
        read, = IO.select([s], nil, nil, $PATIENCE)
        retry unless read.nil? # indicates timeout rather than available IO
      end
    end

    raise IOError.new "No one responded to query" if reply.nil?

    unless responder.ip_address == $NAMESERVERS[0].ip_address
      $logger.warn "Nameserver '#{$NAMESERVERS[0].ip_address}' was queried, but '#{responder.ip_address}' responded!"
    end

    return reply
  end

  def self.mdns query
    s = Socket.new :INET, :DGRAM, 0
    s.bind Addrinfo.udp("0.0.0.0", 0)
 
    s.sendmsg query.encode, 0, Addrinfo.udp("224.0.0.251", 5353) # Standard mDNS multicast address

    begin
      reply, responder = s.recvmsg_nonblock
    rescue IO::WaitReadable
      read, = IO.select([s], nil, nil, $PATIENCE)
      retry unless read.nil?
      raise IOError "No one responded to query for #{query.question[0].qname}"
    end

    return reply
  end
end

class Server
  def initialize addr
    @addr = addr
    @family = addr.ipv4? ? :INET : :INET6

    @socket = Socket.new @family, :DGRAM, 0
    @socket.bind addr
  end

  attr_reader :addr

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
    domain.end_with?("local") ? Resolver.mdns(query) : Resolver.dns(query)
  end

  def resolve_query packet, client
    query = DNS::Message.decode packet

    # in theory the DNS protocol can handle multiple requests
    # but in practice they reject any request that does this
    raise EncodingError unless query.question.length == 1
    question = query.question[0]

    if records = $CACHE.fetch(question.qname, question.qtype)
      $logger.debug "Query from #{client.ip_address}:#{client.ip_port} - #{question.qname} #{question.qtype} (cache hit)"
      query.answer = records
      reply = query.response!

      @socket.sendmsg reply.encode, 0, client
    else
      $logger.debug "Query from #{client.ip_address}:#{client.ip_port} - #{question.qname} #{question.qtype} (cache miss)"
      packet = forward_query query
      @socket.sendmsg packet, 0, client

      reply = DNS::Message.decode packet
      $CACHE.store(question.qname, question.qtype, reply.answer + reply.authority)
    end

  rescue EncodingError
    @socket.sendmsg query.fail_format!.encode, 0, client
  rescue Exception => e
    @socket.sendmsg query.fail_server!.encode, 0, client
    $logger.error "Internal server failure!"
    raise e
  end

end

def main
  scheduler = Async::Scheduler.new
  Fiber.set_scheduler(scheduler)

  servers = $ENDPOINTS.each_with_object([]) {|addr,arr| arr << Server.new(addr) }

  servers.each do |s|
    $logger.info "Server listening on #{s.addr.ip_address}:#{s.addr.ip_port}"
    Fiber.schedule { s.run }
  end
end

main if __FILE__ == $0
