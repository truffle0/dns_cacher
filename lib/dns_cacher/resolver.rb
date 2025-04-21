#frozen_string_literal: true

require_relative 'dns'
require 'socket'

module DNSCacher
  def self.parse_nameservers(source = "/etc/resolv.conf")
    File.open(source).readlines.each_with_object([]) do |line, arr|
      md = /^nameserver\s+(?'addr'.*)(\s*#.*)?/.match(line)
      next if md.nil?  # we're only interested in nameservers

      # skip loopback addresses (that's this server)
      addr = Addrinfo.udp(md[:addr], 53)
      next if addr.ipv4_loopback? or addr.ipv6_loopback?

      arr << addr
    end
  end
  
  # TODO: overhaul and create resolver class
  module Resolver
    # TODO: needs to be configurable at runtime
    MDNS_DOMAIN = /.*\.local$/

    # How long in seconds (by default) the resolver is willing to wait for a reply
    PATIENCE = 3

    # How many times servers will be retried before giving up
    RETRIES = 2

    def self.general_query(query, nameservers)
      domain = query.question[0].qname
      if MDNS_DOMAIN.match? domain
        self.mdns(query)
      else
        self.dns(query, nameservers)
      end
    end

    # Query 'nameservers' in order until one responds, or raise error
    #
    # This is done directly instead of through the Resolv
    # class to reuse existing encoding, and to allow
    # later expansion to support more advanced protocols like DNSSEC
    #
    # (Personally, I also just wanted to learn about the DNS protocol)
    def self.dns(query, nameservers, patience: PATIENCE)
      raise IOError.new "No available nameservers" if nameservers.empty?

      # Create a new socket for the outbound connection, and bind to an available port
      s = Socket.new :INET, :DGRAM, 0
      s.bind Addrinfo.udp('0.0.0.0', 0)

      # forward query onto each available nameserver in turn
      # until we get a response
      packet = query.encode
      reply, responder = (nameservers * RETRIES).each do |server|
        s.sendmsg packet, 0, server

        begin
          reply, responder = s.recvmsg_nonblock
          break reply, responder
        rescue IO::WaitReadable
          read, = IO.select([s], nil, nil, PATIENCE)
          break nil if read.nil? # indicates timeout rather than available IO
          retry
        end
      end

      raise IOError.new "No response" if reply.nil?
      
      # TODO: proper checks and warnings
      #unless responder.ip_address == nameservers[0].ip_address
      #  raise IOError.new "Nameserver '#{nameservers[0].ip_address}' was queried, but '#{responder.ip_address}' responded!"
      #end

      return reply
    end

    def self.mdns(query, patience: PATIENCE)
      s = Socket.new :INET, :DGRAM, 0
      s.bind Addrinfo.udp("0.0.0.0", 0)

      s.sendmsg query.encode, 0, Addrinfo.udp("224.0.0.251", 5353) # Standard mDNS multicast address

      begin
        reply, responder = s.recvmsg_nonblock
      rescue IO::WaitReadable
        read, = IO.select([s], nil, nil, PATIENCE)
        retry unless read.nil?
        raise IOError.new "No one responded to query for #{query.question[0].qname}"
      end

     return reply
    rescue IOError
      # With mDNS no response means success but server doesn't exist
      return nil
    end
  end
end
