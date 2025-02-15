require_relative 'packet'
require_relative 'decoders'

##
# Representation and operations for DNS-related structures and packets
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

    # Definitions of standard types from RFC-1035
    A = def_type(:A, 1, address: "CCCC")
    NS = def_type(:NS, 2, nsdname: "Z*")
    MD = def_type(:MD, 3, madname: "Z*")
    MF = def_type(:MF, 4, madname: "Z*")
    CNAME = def_type(:CNAME, 5, cname: "Z*")
    SOA = def_type(:SOA, 6, {
        mname: "Z*",
        rname: "Z*",
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
    WKS = def_type(:WKS, 11, address: "CCCC", protocol: "C", bitmap: "B*")
    PTR = def_type(:PTR, 12, ptrdname: "Z*")
    HINFO = def_type(:HINFO, 13, cpu: "Z*", os: "Z*")
    MINFO = def_type(:MINFO, 14, rmailbx: "Z*", emailbx: "Z*")
    MX = def_type(:MX, 15, preference: "Z*", exchange: "Z*")
    TXT = def_type(:TXT, 16, txtdata: "Z*")
    
    # allow standard types to be identified
    @@standard = [
      A, NS, MD, MF, CNAME, SOA, MB, MG, MR,
      NULL, WKS, PTR, HINFO, MINFO, MX, TXT
    ]
    def is_standard?(type) = @@standard.contains?(type)

  end

  module QType
    # Define additional QTypes from the

    include Type
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
      name: "Z*",
      type: "n",
      dclass: "n",
      ttl: "N",
      rdlength: "n" 
    }

    HIDDEN = [ :rdlength ]

    CONST = {
      type: Type.type_ids,
      dclass: DClass.class_ids,
    }

    def initialize(fields = {})
      super(fields)

      rstruct = Type.struct self.type
      raise "Type '#{type}' not found!" if rstruct.nil?

      for k in rstruct.keys
        @fields[k] = fields[k]
      end
    end

    ##
    # Encode the +Record+ in binary format
    def encode
      # encode the rdata, then set the field length in the header
      rdata = _encode(Type.struct(self.type), self.rdata)
      @fields[:rdlength] = rdata.length
      
      # encode header
      header = super
      
      return header + rdata
    end

    ##
    # Decode a record from a binary packet
    def self.decode_with_offset(packet, offset = 0)
        # Decode header, and save the rest of the string as a remainder
        head, off = Decode.by_pattern(packet, self::HEADER, offset: offset)
        unless head[:rdlength] == (packet.length - off)
          raise EncodingError.new("reported rdata length #{head[:rdlength]} != actual length #{remainder.length}")
        end

        rdata, off = Decode.by_pattern(packet, Type.struct(to_const(:type, head[:type])), offset: off)
        
        return self.new(head.merge(rdata)), off
    end

  end

  class Question < Packet
    HEADER = {
      qname: ["CA*"], # requires special handling during encode/decode
      qtype: "n",
      qclass: "n",
    }

    HIDDEN = [ :len ]

    CONST = {
      qtype: Type.type_ids,
      qclass: DClass.class_ids,
    }

    def encode
      domain = Encode::domain_string_array(self.qname)
      tail = Encode::by_pattern(@fields, self.HEADER.except(:qname))

      return domain + tail
    end
    
    def self.decode_with_offset(packet, offset=0)
      # decode domain strings
      strings, offset = Decode::domain_string_array(packet, offset: offset)
      domain = { qname: strings }

      tail, offset = Decode::by_pattern(packet, self::HEADER.except(:qname), offset: offset)

      return self.new(domain.merge(tail)), offset
    end
  end

  class Message < Packet
    HEADER = {
      id: "n",
      _flags: "n",
      #qr: "B",
      #opcode: "h",
      #aa: "B",
      #tc: "B",
      #rd: "B",
      #ra: "B",
      #z: "B",
      #rcode: "h",
      qdcount: "n",
      ancount: "n",
      nscount: "n",
      arcount: "n",
    }

    # definitions for flag variables
    FLAGS = {
      qr: 0x8000, # bit 0
      opcode: 0x7800, # bits 1-4
      aa: 0x0400, # bit 5
      tc: 0x0200, # bit 6
      rd: 0x0100, # bit 7
      ra: 0x0080, # bit 8
      z: 0x01C0, # bits 9-11
      rcode: 0x000F, # bits 12-15
    }
    def FLAGS = self.class::FLAGS
    
    def method_missing(name, *args)
      base = String(name).delete_suffix("=").to_sym

      if self.FLAGS.include? base
        mask = self.FLAGS[base]
        
        # getter: use bitmask to check value
        self.class.define_method base do
          return @fields[:_flags] & mask != 0
        end

        self.class.define_method "#{base}=" do |x|
          x ? @fields[:_flags] |= mask : @fields[:_flags] &= ~mask
          return x
        end

        return self.method(name).(*args)
      end

      return super(name, *args)
    end

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
    
    

    HIDDEN = [ :_bitflags, :qdcount, :ancount, :nscount, :arcount ]
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
      
      define_method "add_#{name}" do |vars|
        n = [n] unless n.respond_to? :each

        n.each do |n|
          raise "Invalid type, expected #{type}" unless n.is_a? type
          @fields[name] << n
        end
      end
    end

    def initialize(fields = {})
      super(fields)

      self.SECTIONS.each do |key, type|
        f = fields.fetch(key, [])
        f.all? {|n| n.is_a? type} or raise "Invalid type, section #{key} expects a #{type.name}"

        @fields[key] = f
      end
    end

    def encode
      # updates counts, in case they're been modified
      @fields.merge({
        qdcount: self.qdcount,
        ancount: self.ancount,
        nscount: self.nscount,
        arcount: self.arcount,
      })
      
      header = Encode.by_pattern(@fields, self.HEADER)
      
      sections = @fields.fetch_values(:question, :answer, :authority, :additional).flatten
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
        a, offset = Record.decode(packet, offset)
        sections[:authority] << a
      end

      sections[:additional] = []
      header[:arcount].times do
        a, offset = Record.decode(packet, offset)
        sections[:additional] << a
      end
      
      return self.new(header.merge(sections)), offset
    end
  end
end
