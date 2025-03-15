require 'socket'

require 'async'
require 'async/barrier'
require 'async/semaphore'

module DNSCacher
  class Endpoint
    attr_reader :addr, :family, :semaphore

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
    end

    def run(&handler)
      loop do
        packet, client, = @socket.recvmsg

        # Spawn async query handler using use block
        @semaphore.async do |task|
          # call handler, capture reply and relay back to client
          reply = handler.call(packet)
          raise EncodingError.new("Expecting a string, but received #{reply.class}") unless reply.is_a? String
          
          @socket.sendmsg reply, 0, client
        end
      end
    ensure
      # Force all running handlers to complete, when endpoint is closing down
      @barrier.stop
    end

    def finalize obj_id
      @socket.close
    end
  end
end
