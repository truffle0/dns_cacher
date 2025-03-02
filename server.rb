#!/bin/env ruby

require 'socket'
require 'thread'
require 'logger'
require_relative 'dns'

$logger = Logger.new(STDOUT)

$SERVERS = [
  Addrinfo.udp("127.0.0.1", 1053),
  Addrinfo.udp("127.0.0.1", 53),
]

##
# Parses /etc/resolv.conf to determine system nameservers
def get_nameservers
  ns = /^nameserver\s*([\d\.:]+)\s*$/
  servers = []
  
  File.open("/etc/resolv.conf") do |f|
    f.readlines.each do |line|
      servers << ns.match(line)[1] if ns.match? line
    end
  end

  return servers.map{|x| IPAddr.new x}
end

class RecordCache
  CacheKey = Struct.new(:name, :type)
  CacheQuery = Struct.new(:records, :expiry)

  def initialize
    @cache = {}
    @lock = Mutex.new
  end
  
  def add(domain, type, records)
    String(domain)
    raise TypeError.new("Type '#{type}' not a Symbol") unless type.is_a? Symbol
    
    # find the minimum ttl in the records (ttl 0 will not be cached)
    ttl = records.map{|x| x.ttl}.min
    return false if ttl == 0
    
    key = CacheKey.new(domain, type)
    value = CacheQuery.new(records, Time.now(in: ttl))

    @lock.synchronize{ @cache[key] = value }
    return true
  end
  
  def search(domain, type)
    key = CacheKey.new(domain, type)
    rec = @lock.synchronize { @cache[key] }
    
    return rec.nil? ? nil : rec.records

  end

  def scan
    now = Time.now
    @lock.synchronize do
      @cache.filter!{|key, val| val.expiry > now}
    end

    return
  end
end

class Server
  def initialize(queue = nil, cache = nil)
    @sockets = $SERVERS.each_with_object([]) do |addr, arr|
      begin
        sock = Socket.new :INET, :DGRAM, 0
        sock.bind addr
        arr << sock
        
        $logger.info("Server listening on #{addr.pfamily == Socket::SOCK_DGRAM ? "UDP" : "TCP"} #{addr.ip_address}:#{addr.ip_port}")
      rescue SocketError, Errno::EACCES => e
        $logger.warn("Binding server port #{addr.ip_address}:#{addr.ip_port} failed: #{e}")
      end
    end

    @cache = cache.nil? ? $CACHE : cache
    @queue = queue.nil? ? $QUEUE : queue
  end

  def enter
    loop do
      IO.select(@sockets)[0].each do |sock|
        begin
          # recv request
          packet, addr, *_ = sock.recvmsg_nonblock
        
          # decode message and parse question
          query = DNS::Message.decode packet
          @queue << [query, addr, sock]
        rescue EncodingError => e
          $logger.error "Query decode failed!\n#{e}"
          next
        end

      end
    end
  end

  def spawn 
    raise ThreadError.new("Worker thread already running!") unless @thread.nil?
    t = Thread.new{enter}
    @thread = t
  end
end

class ResolvWorker
  def initialize(queue = nil, cache = nil)
    @queue = queue.nil? ? $QUEUE : queue
    @cache = cache.nil? ? $CACHE : cache

    @client = nil
    @thread = nil
  end
  
  def enter
    loop do
      query, ret_addr, serv_sock = @queue.pop

      begin
        raise TypeError.new("Unsupported DNS operation #{query.opcode}") if query.opcode != 0

        # only allow a single question, like all dns servers in the wild
        question = query.question.first
        
        if records = @cache.search(question.qname, question.qtype)
          $logger.debug "Cache hit: #{question.qname}"
          resp = query_answer! query, records
        else
          $logger.debug "Cache miss: #{question.qname}"
          resp = DNS::Message.decode forward_query(query.encode)

          # cache returned values, but keep response as is
          if resp.qr and resp.rcode == 0 and resp.opcode == 0 and not resp.answer.empty?
            @cache.add(question.qname, question.qtype, resp.answer)
          else
            $logger.debug "Transaction #{resp.id}, for #{resp.question[0].qname}, not cache-able"
          end
        end
      rescue EncodingError => e
        $logger.debug "Transaction #{query.id} failed due to server error!\n#{e}"
      rescue TypeError => e
        $logger.debug "Query type unsupported: #{e}"
        resp = query_unsupported! query
      ensure
        # for internal server errors, inform the client
        resp ||= query_failure query.id, question.question

        # at least something must be sent
        serv_sock.send resp.encode, 0, ret_addr
      end
    end
  end

  def spawn
    raise ThreadError.new("Worker thread already running!") unless @thread.nil?
    t = Thread.new{enter}
    @thread = t
  end

  def query_failure(id, questions)
    msg = DNS::Message.new(id: id, question: questions)
    # server failure
    msg.rcode = 2

    # set response
    msg.qr = true

    # ensure capabilities are set right
    msg.ra = msg.aa = false

    # clear sections we don't do
    msg.answer.clear()
    msg.authority.clear()
    msg.additional.clear()

    return msg
  end

  def query_unsupported!(msg)
    # return code and caps
    msg.rcode = 4
    msg.qr = true
    msg.ra = msg.aa = false

    msg.answer.clear()
    msg.authority.clear()
    msg.additional.clear()

    return msg
  end

  def query_answer!(msg, answers)
    # return code and caps
    msg.rcode = 0
    msg.qr = true
    msg.ra = msg.aa = false

    # set sections
    msg.answer = answers
    msg.authority.clear()
    msg.additional.clear()
    
    return msg
  end

  def forward_query msg
    s = Socket.new :INET, :DGRAM, 0
    s.bind Addrinfo.udp("0.0.0.0", 0)
    
    # send query and wait for reply
    s.send msg, 0, $NAMESERVERS[0]
    resp, addr, *_ = s.recvmsg
    
    if addr.ip_address != $NAMESERVERS[0].ip_address
      $logger.warn "Sent query to #{$NAMESERVERS[0].ip_address}, but received reply from #{addr.ip_address}"
    end

    return resp
  ensure
    s.close
  end
end

def main
  # Fetch nameservers excluding loopback
  $NAMESERVERS = get_nameservers().filter{|x| not x.loopback?}.map{|x| Addrinfo.udp x.to_s, 53}
  $NAMESERVERS.each { |x| $logger.info "Using upstream nameserver: #{x.ip_address}:#{x.ip_port}" }
 
  # create queue and cache
  $QUEUE = Queue.new
  $CACHE = RecordCache.new

  # start server loop
  Server.new.spawn
  ResolvWorker.new.enter
end

main() if __FILE__ == $0
