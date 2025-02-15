module Decode
  def self.by_pattern(data, pattern = {}, offset: 0)
    Hash(pattern)
    String(data)
    
    *out, tail = data.unpack("#{pattern.values.join}a*", offset: offset)

    parsed = {}
    values = out.each
    pattern.each do |field, shape|
      # determine the number of characters in the field, i.e. the number of elements
      # from the parsed array to collect for it (skips control characters 'x' and 'X')
      n = shape.scan(/\p{L}/).filter{|x| not 'xX'.include? x}.count
      
      # collect the number of values to match the field
      # or, if only 1, just great the next one (without wrapping in an Array)
      parsed[field] = n > 1 ? values.take(n) : values.next
    end
     
    return parsed, offset + (data.length - tail.length)
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

    strings = []
    loop do
      len = data.unpack1("C", offset: offset)
      offset += 1

      break if len == 0

      str = data.unpack1("a#{len}", offset: offset)
      unless str.ascii_only?
        raise EncodingError.new("Domain string '#{str}' is invalid!")
      end

      strings << str
      offset += str.length
    end

    return strings, offset
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
    field_list = pattern.keys.each_with_object([]){|f, arr| arr << fields[f]}.flatten
    encoding = pattern.values.join

    return field_list.pack(encoding)
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
    encoding = ""
    data.each do |str|
      if str.length > 63 or not str.ascii_only?
        raise EncodingError("String '#{str}' exceeds max length of 63-bytes")
      end
      
      encoding << [ str.length, str ].pack("CA*")
    end

    # Append null byte
    encoding << "\x00"
    return encoding
  end
end
