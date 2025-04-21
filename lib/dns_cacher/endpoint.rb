#frozen_string_literal: true

require 'socket'
require 'async'
require 'async/barrier'
require 'async/semaphore'

module DNSCacher
  
  # Server endpoint for clients to connect to
  class Endpoint
    attr_reader :addr, :family, :semaphore
    
    # Initialize Endpoint, currently only supports datagram mode
    # @parameter addr [Addrinfo] Address for endpoint to (attempt to) bind to
    # @parameter
    #
    # @raises [SocketError] If endpoint cannot be bound for any reason
    def initialize(addr, max_handlers=10)
      @addr = addr
      @family = addr.ipv4? ? :INET : :INET6

      # initialize endpoint server socket from 'addr'
      @socket = Socket.new @family, :DGRAM, 0
      @socket.bind addr

      # limit the maximum number of active handlers per endpoint
      # exceeding will halt reading new data temporarily
      @barrier = Async::Barrier.new
      @semaphore = Async::Semaphore.new(max_handlers, parent: @barrier)
    rescue SystemCallError => e
      raise SocketError.new e.detailed_message 
    end
    
    # Run Endpoint, accepts queries from clients and returns response
    # @parameter handler [Proc] Block to handle queries, must accept and return a {DNS::Message}
    def run(&handler)
      loop do
        packet, client, = @socket.recvmsg

        # Spawn async query handler using use block
        # Passing 'client' and 'packet' is required to ensure the block
        # doesn't try to reference outside it's scope (as these variables will likely change)
        @semaphore.async(client, packet) do |task, client, packet|
          # call handler, capture reply and relay back to client
          reply = handler.call(packet)
          raise EncodingError.new("Expecting binary string, but received #{reply.class}") unless reply.is_a? String

          @socket.sendmsg reply, 0, client
        end
      end
    ensure
      # Force all running handlers to complete, when endpoint is closing down
      @barrier.stop
    end

    private
    def finalize obj_id
      @socket.close
    end
  end
end
