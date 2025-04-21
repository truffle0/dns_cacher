require_relative 'dns'

require 'async'
require 'async/barrier'

module DNSCacher
  # Cache responses from DNS queries, automatically purges once TTL has expired
  class Cache
    
    # Used to key both domain and record-type
    CacheKey = Struct.new(:domain, :rcode)
    
    # Initialize Cache
    def initialize
      @cache = {}

      # For tracking/cleanup of timer tasks
      @barrier = Async::Barrier.new
    end
    
    # Stores 1 or more records key'd by domain and record type
    # Will no cache if *any* of the records have a TTL of 0
    # @asyncronous Will purge records asyncronously after *smallest* TTL expires
    #
    # @parameter domain [String] Domain name
    # @parameter rcode [Symbol] DNS record type
    # @parameter records [[DNS::Record]] Array of records to cache
    #
    # @returns [[DNS::Record]|nil] Returns all records cache, otherwise nil
    def store(domain, rcode, records)
      ttl = records.map{|x| x.ttl}.min
      key = CacheKey.new(domain, rcode)

      if ttl.nil? or ttl == 0
        return nil
      end

      @cache[key] = records
      
      # Async timer to purge record
      @barrier.async do
        sleep ttl
        @cache.delete key
      end

      return records
    end
    
    # Fetch stored records, if they exist
    # @parameter domain [String] Domain name
    # @parameter rcode [Symbol] DNS Record type
    #
    # @returns [[DNS::Record]|nil]
    def fetch(domain, rcode)
      @cache.fetch(CacheKey.new(domain, rcode), nil)
    end

    private

    # Reaps all pending timers
    # @private
    def finalize obj_id
      @barrier.stop
    end
  end
end
