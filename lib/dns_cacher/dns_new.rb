require_relative 'packet'
require_relative 'decoders'

module DNS
  module Record
    @@header = [:name, :type, :dclass, :ttl, :rdlength]

    def Record.def_type(id, struct)
      return Struct.new(*(@@header + struct.keys)) do
        
      end
    end

    Struct.new("Type", :id, :rdata) do
      def to_i = self.id
      def to_hash = self.rdata
    end

    A = Type(1, address: :ipv4_addr)
    
  end

  module DClass

  end

  class Record < Packet
    HEADER = [ :name, :type, :dclass, :ttl, :rdlength ]
    PATTERN = [ :domain_string_array, "n", "n", "N", "n" ]

    def encode
      
    end

    def self.decode_with_offset(packet, offset = 0)

    end


  end
end
