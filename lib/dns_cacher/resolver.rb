#frozen_string_literal: true

require_relative 'dns'
require 'socket'

module Resolver
  # Parse nameserver Addrinfo from resolv.conf or similarly formatted sources
  def self.parse_nameservers(source)
      source.lines.each_with_object([]) do |line, acc|
        md = /^nameserver\s+(?'addr'.*)(\s*#.*)?/.match(line.chomp)
        next if md.nil?

        addr = Addrinfo.ip(md[:addr])
        next if addr.ipv4_loopback? or addr.ipv6_loopback?

        acc << addr
      end
  end

  # Resolver that uses sends DNS requests over UDP
  class Basic
    def initialize(nameservers = [], patience = 0.5, retries = 2)
      self.nameservers = nameservers
      @patience = patience
      @retries = retries
    end

    attr_reader :nameservers
    def nameservers=(nameservers)
      @nameservers = nameservers.collect do |addr|
        addr = addr.ip_address if addr.is_a?(Addrinfo)
        Addrinfo.udp(addr, 53)
      end.freeze
    end

    def query(msg)
      raise IOError.new "No available nameservers" if @nameservers.empty?
      msg = msg.encode if msg.is_a? DNS::Message
      raise TypeError.new "Invalid query" unless msg.is_a? String

      # IPv6 sockets can accept ipv4 packets too
      sock = Socket.new :INET6, :DGRAM, 0
      sock.bind Addrinfo.udp("::", 0)

      reply, responder = (nameservers * @retries).each do |server|
        sock.sendmsg msg, 0, server

        begin
          reply, responder = sock.recvmsg_nonblock
          break reply, responder
        rescue IO::WaitReadable
          read, = IO.select([sock], nil, nil, @patience)
          retry unless read.nil?
          break nil
        end
      end

      return reply
    rescue
      attempts ||= @retries
      attempts = attempts - 1
      
      retry unless attempts <= 0
      return nil
    ensure
      sock.close if defined? sock
    end

    def resolve(domain, record = :A)
      ques = DNS::Question.new(qname: domain, qtype: record, qclass: :IN)
      msg = DNS::Message.new(id: Random.rand(), question: ques)
      msg.query!

      answer = self.query(msg)
      return nil if answer.nil?

      DNS::Message.decode(answer).answer
    end
  end

  class Multicast
    def initialize(patience = 5, retries = 2)
      @patience = patience
      @retries = retries
    end

    def query(msg)
      msg = msg.encode if msg.is_a? DNS::Message
      raise TypeError.new "Invalid query" unless msg.is_a? String

      sock = Socket.new :INET, :DGRAM, 0
      sock.bind Addrinfo.udp("0.0.0.0", 0)

      # Standard mDNS multicast address
      sock.sendmsg msg, 0, Addrinfo.udp("224.0.0.251", 5353)

      begin
        reply, responder = s.recvmsg_nonblock
      rescue IO::WaitReadable
        read, = IO.select([s], nil, nil, @patience)
        retry unless read.nil?
        reply = nil
      end

      return reply
    ensure
      sock.close if defined? sock
    end

    def resolve(domain, record = :A)
      ques = DNS::Question.new(qname: domain, qtype: record, qclass: :IN)
      msg = DNS::Message.new(id: Random.rand(0..65535), question: ques)

      answer = self.query(msg)
      return nil if answer.nil?

      answer.answer[0]
    end

  end
end
