require 'async'
require 'logger'

require_relative 'dns'

module Server
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
end
