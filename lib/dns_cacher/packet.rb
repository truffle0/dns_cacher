require_relative 'decoders'

##
# Class for efficiently storing encoding/decoding data in network packets
# Intended to provide a basic and expandable implementation
class Packet
  ##
  # defines the structure of the packet header
  # if the packet has no variable structure this can be used for the whole packet
  HEADER = nil
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
  CONST = nil
  def CONST = self.class::CONST

  ##
  # fields that exist, but should not be set directly
  # these should be generated before encoding, and
  # given custom accessors
  #
  # isn't required to be an array, only needs to implement 'include?'
  HIDDEN = [ :_flags ]
  def HIDDEN = self.class::HIDDEN

  FLAGS = nil
  def FLAGS = self.class::FLAGS

  def initialize(fields = {})
    @fields = {}
    for k in self.HEADER.except(self.HIDDEN).keys
      @fields[k] = from_const(k, fields[k])
    end
  end

  def encode()
    Encode::by_pattern(@fields, self.HEADER)
  end

  ##
  # Decode a binary string into a packet, decode_head will never return
  # trailing un-decoded data, even if it is present
  def self.decode_with_offset(data, offset = 0)
    fields, offset = Decode::by_pattern(data, self::HEADER, offset: offset)
    pk = self.new(fields)

    return pk, offset
  end


  def self.decode(packet)
    return decode_with_offset(packet).first
  end

  ##
  # base implementation checks whether
  # all values will pack according to the defined structure
  def valid?
    begin
      for f, v in @fields
        next unless v.is_a? String # allow special handling for place-holder fields
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
    if self.HEADER.except(*self.HIDDEN).include? base
      self.class.define_method base do
        to_const(base, @fields[base])
      end

      self.class.define_method "#{base}=" do |n|
        @fields[base] = from_const(base, n)
      end

      return self.method(name).(*args)
    elsif @fields.include? :_flags and self.FLAGS.include? base
      mask = self.FLAGS[base]

      self.class.define_method base do
        Integer(@fields[:_flags]).anybits?(mask)
      end

      self.class.define_method "#{base}=" do |x|
        x ? @fields[:_flags] |= mask : @fields[:_flags] &= ~mask
      end

      return self.method(name).(*args)
    elsif @fields.except(*self.HIDDEN).include? base
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
