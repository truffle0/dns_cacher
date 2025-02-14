require_relative 'packet'

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

      puts @fields

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
    def self.decode(packet)
        # Decode header, and save the rest of the string as a remainder
        head, remainder = _decode(self::HEADER, packet)
        raise EncodingError.new("reported rdata length #{head[:rdlength]} != actual length #{remainder.length}") unless head[:rdlength] == remainder.length

        rdata = _decode(Type.struct(to_const(:type, head[:type])), remainder)

        return self.new(head.merge(rdata))
    end

  end
end
