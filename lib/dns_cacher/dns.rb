require_relative 'packet'
require_relative 'decoders'

##
# Representation and operations for DNS-related structures and packets
#
# Exists as a proof-of-concept/alternate implementation, as Ruby already
# has classes such as Resolv::DNS::Message that encapsulate these types.
# This implementation may be used later to expand functionality however
#
# TODO: overhaul entire module, implementation is functional but messy
module DNS
  module Type
    @@type_ids = {}
    @@rdata_patterns = {}

    def Type.type_ids = @@type_ids
    def Type.struct(type) = @@rdata_patterns[type]
    def Type.id(type) = @@type_ids[type]

    def Type.def_type(sym, id, struct)
      sym.is_a? Symbol || raise("'#{sym}' not a symbol!")
      @@type_ids[sym] = Integer(id)
      @@rdata_patterns[sym] = Hash(struct)
      return sym
    end

    def Type.undef_type(sym)
      @@standard.delete(sym)
      @@type_ids.delete(sym)
      @@rdata_patterns.delete(sym)
    end

    # RFC-1035
    A = def_type(:A, 1, address: :ipv4_addr)
    NS = def_type(:NS, 2, nsdname: "Z*")
    MD = def_type(:MD, 3, madname: "Z*")
    MF = def_type(:MF, 4, madname: "Z*")
    CNAME = def_type(:CNAME, 5, cname: :domain_string_array)
    SOA = def_type(:SOA, 6, {
        mname: :domain_string_array,
        rname: :domain_string_array,
        serial: "N",
        refresh: "N",
        retry: "N",
        expire: "N",
        minimum: "N"
    })
    MB = def_type(:MB, 7, madname: "Z*")
    MG = def_type(:MG, 8, mgmname: "Z*")
    MR = def_type(:MR, 9, newname: "Z*")
    NULL = def_type(:NULL, 10, data: "Z*")
    WKS = def_type(:WKS, 11, address: :ipv4_addr, protocol: "C", bitmap: "B*")
    PTR = def_type(:PTR, 12, ptrdname: "Z*")
    HINFO = def_type(:HINFO, 13, cpu: "Z*", os: "Z*")
    MINFO = def_type(:MINFO, 14, rmailbx: "Z*", emailbx: "Z*")
    MX = def_type(:MX, 15, preference: "Z*", exchange: "Z*")
    TXT = def_type(:TXT, 16, txtdata: "Z*")

    # RFC-3596
    AAAA = def_type(:AAAA, 28, address: :ipv6_addr)

    # RFC-2671
    # OPT = def_type(:OPT, 41, ...)

    # RFC-9460
    #SVCB = def_type(:SVCB, ...)
    #HTTPS = def_type(:HTTPS, ...)

    # allow standard types to be identified
    @@standard = [
      A, NS, MD, MF, CNAME, SOA, MB, MG, MR,
      NULL, WKS, PTR, HINFO, MINFO, MX, TXT,
      AAAA,
    ]
    def is_standard?(type) = @@standard.contains?(type)

  end

  module QType
    # Define additional QTypes from the

    include Type

    # RFC-1035
    AXFR = Type.def_type(:AXFR, 252, nil)
    MAILB = Type.def_type(:MAILB, 253, nil)
    MAILA = Type.def_type(:MAILA, 254, nil)
    ALL = Type.def_type(:*, 255, nil) # '*' in RFC-1035

  end

  module DClass
    @@class_ids = {}

    def DClass.class_ids = @@class_ids
    def DClass.id(dclass) = @@class_ids[dclass]

    def DClass.def_class(sym, id)
      sym.is_a? Symbol || raise("'#{sym}' not a symbol!")
      @@class_ids[sym] = id
      return sym
    end


    # Standard classes from RFC-1035
    IN = def_class(:IN, 1)
    CS = def_class(:CS, 2)
    CH = def_class(:CH, 3)
    HS = def_class(:HS, 4)

    # create an identifier for standard classes
    @@standard = [ IN, CS, CH, HS ]
    def is_standard?(cls) = @@standard.contains?(cls)
  end

  module QClass
    include DClass
    ALL = DClass.def_class(:*, 255) # '*' in RFC-1035
  end

  class Record < Packet
    ##
    # Value for the +rdlength+ field of the DNS Record struct
    #
    # Require for encode/decode, but can be calculated on the fly
    def rdlength = _encode(Type.struct(self.type), self.rdata).length
    def rdata = Type.struct(self.type).keys.map.with_object({}) { |k, h| h[k] = @fields[k] }

    HEADER = {
      name: :domain_string_array, # domain string array
      type: "n",
      dclass: "n",
      ttl: "N",
      rdlength: "n",
    }

    HIDDEN = [ :rdlength ]

    CONST = {
      type: Type.type_ids,
      dclass: DClass.class_ids,
    }

    def initialize(fields = {})
      super(fields)

      rstruct = Type.struct self.type

      # accept arbitrary rdata if the type isn't known
      rstruct = { rdata: "" } if rstruct.nil?

      for k in rstruct.keys
        @fields[k] = fields[k]
      end
    end

    ##
    # Encode the +Record+ in binary format
    def encode
      # encode the rdata, then set the field length in the header
      rstruct = Type.struct(self.type)
      rstruct = { rdata: "a*" } if rstruct.nil?
      rdata = Encode.by_pattern(@fields, rstruct)

      @fields[:rdlength] = rdata.length

      # encode domain name string, then the rest of the header separately
      header = Encode.by_pattern(@fields, self.HEADER)

      return header + rdata
    end

    ##
    # Decode a record from a binary packet
    def self.decode_with_offset(packet, offset = 0)
        fields, offset = Decode.by_pattern(packet, self::HEADER, offset: offset)

        unless fields[:rdlength] <= (packet.length - offset)
          raise EncodingError.new("reported rdata length #{fields[:rdlength]} exceeds the rest of the packet length #{packet.length - offset}")
        end

        record_type = Type.struct(to_const(:type, fields[:type]))
        #raise EncodingError.new("Unrecognised record type: #{fields[:type]}")

        unless record_type.nil?
          rdata, offset = Decode.by_pattern(packet, record_type, offset: offset)
          fields.merge!(rdata)
        else
          # handle unknown rdata types by reading, but not decoding, the buffer
          rdata, offset = Decode.by_pattern(packet, { rdata: "a#{fields[:rdlength]}" }, offset: offset)
          fields.merge!(rdata)
        end

        return self.new(fields), offset
    end

  end

  class Question < Packet
    HEADER = {
      qname: :domain_string_array,
      qtype: "n",
      qclass: "n",
    }

    CONST = {
      qtype: Type.type_ids,
      qclass: DClass.class_ids,
    }
  end

  class Message < Packet
    HEADER = {
      id: "n",
      _flags: "n",
      qdcount: "n",
      ancount: "n",
      nscount: "n",
      arcount: "n",
    }

    # definitions for flag variables
    FLAGS = {
      qr: 0x8000, # Query(0)/Response(1)
      opcode: 0x7800, #opcode: 0 = standard query, 1 = inverse query, 2 = server status
      aa: 0x0400, # Authoritative answer
      tc: 0x0200, # Truncation
      rd: 0x0100, # Recursion Desired
      ra: 0x0080, # Recursion Available
      z: 0x01C0, # Reserved (must be 0)
      #ans_auth
      #data_auth
      rcode: 0x000F, # Response code
    }

    def opcode = (@fields[:_flags] & self.FLAGS[:opcode]) >> 11
    def opcode=(x)
      mask = self.FLAGS[:opcode]
      raise "opcode must be between 0 - 15" unless x.between? 0, 15
      @fields[:_flags] &= ~mask  # set masked area low
      @fields[:_flags] |= x << 11 & mask # logical or to write correct (shifted) values
    end

    # this one doesn't require bit shifting
    def rcode = Integer(@fields[:_flags] & self.FLAGS[:rcode])
    def rcode=(x)
      mask = self.FLAGS[:opcode]
      raise "rcode must be between 0 - 15" unless x.between? 0, 15
      @fields[:_flags] &= ~mask
      @fields[:_flags] |= x & mask
    end


    HIDDEN = [ :_flags, :qdcount, :ancount, :nscount, :arcount ]
    def qdcount = self.question.length
    def ancount = self.answer.length
    def nscount = self.authority.length
    def arcount = self.additional.length

    CONST = {
      qtype: Type.type_ids,
      qclass: DClass.class_ids,
    }

    # sections and their type restrictions
    SECTIONS = {
        question: Question,
        answer: Record,
        authority: Record,
        additional: Record,
    }
    def SECTIONS = self.class::SECTIONS

    SECTIONS.each do |name, type|
      define_method name do
        return @fields[name]
      end
    end

    def initialize(fields = {})
      super(fields)
      @fields[:_flags] = 0 unless fields[:_flags].is_a? Integer

      self.SECTIONS.each do |key, type|
        f = Array(fields.fetch(key, []))
        f.all? {|n| n.is_a? type} or raise "Invalid type, section #{key} expects a #{type.name}"

        @fields[key] = f
      end
    end

    def encode
      # updates counts, in case they're been modified
      @fields.merge!({
        qdcount: self.qdcount,
        ancount: self.ancount,
        nscount: self.nscount,
        arcount: self.arcount,
      })

      header = Encode.by_pattern(@fields, self.HEADER)

      sections = @fields.fetch_values(*self.SECTIONS.keys).flatten
      data = sections.each_with_object([]) do |q, arr|
        arr << q.encode
      end

      return header + data.join
    end

    def self.decode_with_offset(packet, offset = 0)
      header, offset = Decode.by_pattern(packet, self::HEADER)

      # go through and decode each section individually
      sections = {}

      sections[:question] = []
      header[:qdcount].times do
        q, offset = Question.decode_with_offset(packet, offset)
        sections[:question] << q
      end

      sections[:answer] = []
      header[:ancount].times do
        a, offset = Record.decode_with_offset(packet, offset)
        sections[:answer] << a
      end

      sections[:authority] = []
      header[:nscount].times do
        a, offset = Record.decode_with_offset(packet, offset)
        sections[:authority] << a
      end

      sections[:additional] = []
      header[:arcount].times do
        a, offset = Record.decode_with_offset(packet, offset)
        sections[:additional] << a
      end

      return self.new(header.merge(sections)), offset
    end

    ## Methods to convert (in-place) between standard message formats ##
    def fail_format!
      self.qr = true
      self.ra = true
      self.rcode = 1

      self.authority.clear()
      self.additional.clear()

      return self
    end

    # Formats message into
    def fail_server!
      self.qr = true
      self.ra = self.aa = true
      self.rcode = 2

      self.authority.clear()
      self.additional.clear()

      return self
    end

    # Formats message into a standard (successful) response
    def response!
      self.qr = true
      self.ra = self.aa = true
      self.rcode = 0

      self.authority.clear()
      self.additional.clear()

      return self
    end
  end
end
