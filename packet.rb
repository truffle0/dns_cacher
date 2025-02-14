##
# Set of tools for encoding/decoding data in binary packets
class Packet
  ##
  # defines the structure of the packet header
  # if the packet has no variable structure this can be used for the whole packet
  HEADER = {}
  def HEADER = self.class::HEADER

  ##
  # constants, grouped by field
  # structured as follows:
  # {
  #   field: {
  #     SYMBOL: VALUE,
  #     ...
  #   },
  #   ...
  # }
  #
  # equivalent to "#define SYMBOL VALUE"
  # will allow specifying a symbol for a field in place
  # of it's numerical value.
  CONST = {}
  def CONST = self.class::CONST

  ##
  # fields that exist, but should not be set directly
  # these should be generated before encoding, and
  # given custom accessors
  #
  # isn't required to be an array, only needs to implement 'include?'
  HIDDEN = []
  def HIDDEN = self.class::HIDDEN
  
  def initialize(fields = {})
    @fields = {}
    for k in self.HEADER.except(self.HIDDEN).keys
      @fields[k] = from_const(k, fields[k])
    end
  end

  def encode()
    return self._encode(self.HEADER, @fields)
  end

  def self.decode(data)
    fields, _ = self._decode(self::HEADER, data)
    return self.new(fields)
  end

  ##
  # base implementation checks whether
  # all values will pack according to the defined structure
  def valid?
    begin
      for f, v in @fields
        [v].pack(self.HEADER[f])
      end
      return true
    rescue
      return false
    end
  end

  def method_missing(name, *args)
    base = String(name).delete_suffix("=").to_sym

    # define the accessor, then call the method as normal
    # if it fails after this it's your (the user's) fault
    if self.HEADER.except(self.HIDDEN).include? base
      self.class.define_method base do
        to_const(base, @fields[base])
      end

      self.class.define_method "#{base}=" do |n|
        @fields[base] = from_const(base, n)
      end

      return self.method(name).(*args)
    elsif @fields.except(self.HIDDEN).include? base
      # same as above but only uses singleton methods
      # for variables that are present in @fields
      # but *not* HEADER.
      # Prevents potentially transient variables from being
      # permanently added to the class

      define_singleton_method base do
        to_const(base, @fields[base])
      end

      define_singleton_method "#{base}=" do |n|
        @fields[base] = from_const(base, n)
      end

      return self.method(name).(*args)
    end


    return super(name, *args)
  end

  def include?(field)
    return @fields.include? field
  end

  def [](field)
    return @fields[field]
  end
  
  private

  def _encode(pattern, params)
    Hash(pattern)
    Hash(params)

    # collect parameters in correct order
    fields = pattern.keys.map{ |x| params[x] }.flatten
    encoding = pattern.values.join()

    return fields.pack(encoding)
  end
    
  def self._decode(pattern, data)
    Hash(pattern)
    String(data)

    parsed = {}
    
    tail = data
    for field, bin in pattern
      out, *extra, tail = tail.unpack("#{pattern[field]}a*")
      parsed[field] = extra.empty? ? out : [out] + extra
    end
    
    # return remaining characters if they exist, otherwise just the parsed result
    return tail.length != 0 ? [parsed, tail] : parsed
  end
  private_class_method :decode
  
  def self.from_const(field, const)
    return self::CONST.dig(field, const) || const 
  end
  def from_const(*a)
    self.class.from_const(*a)
  end

  def self.to_const(field, value)
    return self::CONST.fetch(field, {}).key(value) || value
  end
  def to_const(*a)
    self.class.to_const(*a)
  end
end
