require 'ipaddr'

module Decode
  ##
  # Decode.by_pattern
  # Parses a hash representing the order/types of fields in the packet
  # and pattern and decodes it into a hash of fields with matching keys
  #
  # @param String Binary Data
  # @param Hash Ordered hash of pattern, keys represent field names & values the data types
  # can be a mix of Strings that get passed directly to the *unpack* function, a symbol of
  # another function within this module that can decode complex data, or a Packet class from which
  # the *decode_with_offset* method will be used
  # 
  # @return Hash Fields with keys matching the pattern param, and values being the parsed data
  def self.by_pattern(data, pattern = {}, offset: 0)
    raise EncodingError.new("Cannot parse empty pattern!") if Hash(pattern).empty?
    String(data)

    parsed = {}
    pattern.each do |field, shape|
      case shape
      when String
        out, *ext, tail = data.unpack("#{shape}a*", offset: offset)
        parsed[field] = ext.length > 0 ? [out] + ext : out
        offset = (data.length - tail.length)
      when Symbol
        parsed[field], offset = self.method(shape).(data, offset: offset)
      when Packet
        raise NotImplementedError
      else
        raise EncodingError.new("Unrecognised shape format: #{shape.class}")
      end

      # determine the number of characters in the field, i.e. the number of elements
      # from the parsed array to collect for it (skips control characters 'x' and 'X')
      #n = shape.scan(/\p{L}/).filter{|x| not 'xX'.include? x}.count
      
      # collect the number of values to match the field
      # or, if only 1, just great the next one (without wrapping in an Array)
      #parsed[field] = n > 1 ? values.take(n) : values.next
    end
     
    return parsed, offset
  end
  
  ##
  # Decode.by_shape
  # Similar to the previous *Decode.by_pattern*, but instead takes an Array
  # then returns parsed values in order, with the last value being the new offset
  #
  # @param String Binary data
  # @param Array Shape of the data to be parsed, can contain a mix of String, Symbols or Packet classes
  def self.by_shape(data, shape = [], offset: 0)
    raise EncodingError.new("Cannot parse empty pattern!") if Array(pattern).empty?
    String(data)

    parsed = []
    pattern.each do |shape|
      case shape
      when String
        out, *ext, tail = data.unpack("#{shape}a*", offset: offset)
        parsed << ext.length > 0 ? [out] + ext : out
        offset = data.length - tail.length
      when Symbol
        parsed[field], offset = self.method(shape).(data, offset: offset)
      when Packet
        raise NotImplementedError
      else
        raise EncodingError.new("Unrecognised shape format: #{shape.class}")
      end
    end

    return *parsed, offset
  end

  ##
  # Decode.domain_string_array.
  # Parses a domain string array starting at *offset*
  # Data is made up of multiple non-null-terminated strings
  # where the length is specified by a single byte at the start
  # 
  # null-byte indicates the end of the data
  #
  # @param [String] data
  # @param [Integer] offset
  #
  # @raise [EncodingError] on any length, parsing or string format issues
  #
  # @return [[String], Integer] All strings in order, new offset
  def self.domain_string_array(data, offset: 0)
    String(data)
    start = offset

    strings = []
    loop do
      # determine field type from first 2 bits:
      # 00 = string
      # 11 = pointer
      # 01/10 = undefined
      type = (data.unpack1("C", offset: offset) & 0xC0) >> 6 # mask bits 1 & 2
      
      case type
      when 0
        # indicates it's a single octet that encodes a strlen (or a null byte)
        len = data.unpack1("C", offset: offset)
        offset += 1

        break if len == 0

        str = data.unpack1("a#{len}", offset: offset)
        raise EncodingError.new("Invalid domain string: '#{str}'") unless str.ascii_only?
      when 3
        # find the actual pointer, which is a word not a byte
        pointer = data.unpack1("n", offset: offset) & 0x3FFF # remove top 2 bits
        offset += 2
        
        unless pointer.between? 0, start-1
          raise EncodingError.new("Invalid or circular name pointer: #{pointer}")
        end
        
        remainder, rem_offset = self.domain_string_array(data, offset: pointer)
        strings += remainder.split('.')

        # final sanity check
        raise EncodingError.new("Invalid or circular name pointer") unless rem_offset < offset
        break
      else
        raise EncodingError.new("Undefined domain string definition")
      end

      strings << str
      offset += str.length
    end

    return strings.join('.'), offset
  end

  ##
  # Decodes an IP address in network byte order starting at *offset*
  #
  # @param [String] data
  # @param [Integer] offset (optional)
  #
  # @raise [EncodingError] when parsing fails, usually due to data being too short
  #
  # @return [IPAddr, Integer] Initialised IP class & new offset
  def self.ipv4_addr(data, offset: 0)
    addr = data.unpack("CCCC", offset: offset).join('.')
    return IPAddr.new(addr, family=Socket::AF_INET), offset + 4
  end
  def self.ipv6_addr(data, offset: 0)
    addr = data.unpack("nnnnnnnn", offset: offset).map{|x| x.to_s(16)}.join(":")
    return IPAddr.new(addr, family=Socket::AF_INET6), offset + 16
  end
end

module Encode
  ##
  # Inverse of Decode::by_pattern, takes a pattern and fields
  # and outputs a formatted byte-string
  #
  # @param [Hash] fields Mapping of field names to data
  # @param [Hash] pattern Mapping of field names to output encoded type
  def self.by_pattern(fields, pattern)
    raise EncodingError.new("Cannot parse empty pattern, for fields: #{fields}") if Hash(pattern).empty?
    Hash(fields)

    encoded = []
    pattern.each do |name, shape|
      case shape
      when String
        encoded << [ fields[name] ].flatten.pack(shape)
      when Symbol
        encoded << self.method(shape).(fields[name])
      when Packet
        raise NotImplementedError
      else
        raise EncodingError.new("Unrecognised shape format: #{shape.class}")
      end
    end

    return encoded.flatten.join
  rescue TypeError => e
    raise EncodingError.new "Encoding failed, missing fields.\nPattern = #{pattern}\nFields = #{fields}"
  end

  ##
  # Inverse of Decode::domain_string_array
  # takes a list of strings and encodes them into the DNS domain string
  # format. Each string is headed by an unsigned byte denoting the size.
  # The last string is followed by a null-byte
  #
  # @param [String] data Strings to encode, no string may exceed 63-bytes
  #   or contain non-alphanumeric characters.
  #
  # @raise [EncodingError] if any String violates length or encoding requirements
  #
  # @return [String] encoded byte-string
  def self.domain_string_array(data)
    data = data.split(".") unless data.is_a? Array
    
    # ASCII-8BIT is the encoding used the pack/unpack functions
    # things get weird later if unicode is used here
    encoding = data.each_with_object("".encode("ASCII-8BIT")) do |str, packed|
      if str.length > 63 or not str.ascii_only?
        raise EncodingError.new("String '#{str}' exceeds max length of 63-bytes")
      end
      
      packed << [str.length].pack("C") << [str].pack("A*")
    end

    # Append null byte
    encoding << "\x00"
    return encoding
  end
  
  require 'socket'

  ##
  # Encodes an IP address, as either an Array, String or IPAddr
  # into a network-ordered ip address
  #
  # @param [String|Array|IPAddr] data, to encode
  #
  # @return [String]
  def self.ipv4_addr(data)
    data = data.join('.') if data.is_a? Array
    addr = IPAddr.new data, Socket::AF_INET
    return addr.hton
  end
  def self.ipv6_addr(data)
    data = data.map{|x| x.to_s(16)}.join(':') if data.is_a? Array
    addr = IPAddr.new data, Socket::AF_INET6
    return addr.hton
  end
end
