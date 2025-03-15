require_relative 'dns'

require 'async'
require 'async/barrier'

module DNSCacher
  # Cache responses from DNS queries
  # automatically purges once TTL has expired
  class Cache
    CacheKey = Struct.new(:domain, :rcode)

    def initialize
      @cache = {}

      # For tracking/cleanup of timer tasks
      @barrier = Async::Barrier.new
    end

    def store(domain, rcode, records)
      ttl = records.map{|x| x.ttl}.min
      key = CacheKey.new(domain, rcode)

      if ttl.nil? or ttl == 0
        return nil
      end

      @cache[key] = records

      @barrier.async do
        sleep ttl
        @cache.delete key
      end

      return records
    end

    def fetch(domain, rcode)
      @cache.fetch(CacheKey.new(domain, rcode), nil)
    end

    def finalize obj_id
      @barrier.stop
    end
  end
end
