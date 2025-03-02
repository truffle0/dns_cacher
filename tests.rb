#!/bin/env ruby

puts "Test 1 - Load DNS module"
require_relative 'dns'
puts "\x1B[1FTest 1 - Load DNS - Success"

puts "Test 2 - Create DNS::Record"
r = DNS::Record.new({
  name: "gentoo.org",
  type: :A,
  dclass: :IN,
  ttl: 30,
  address: [192, 168, 1, 32]
})
puts "\x1B[1FTest 2 - Create DNS::Record - Success"
puts r

puts "Test 3 - Encode/Decode"
encoded = r.encode
decoded = DNS::Record.decode(encoded)
puts "\x1B[1FTest 3 - Encode/Decode - Success"
puts encoded
puts decoded

puts "Test 4 - Decode a real message packet"
packets = [
  "\xFA\xBD\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03cdn\bghostery\x03com\x00\x00\x01\x00\x01\xC0\f\x00\x05\x00\x01\x00\x00\x00g\x00\x18\fghostery-cdn\x05b-cdn\x03net\x00\xC0.\x00\x01\x00\x01\x00\x00\x00\b\x00\x04\x9C\x928\xAA",
  "\xEE4\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\fsafebrowsing\ngoogleapis\x03com\x00\x00\x01\x00\x01\xC0\f\x00\x01\x00\x01\x00\x00\x00\xCF\x00\x04\x8E\xFAB\xEA",
  "\xFD\x19\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\rgae2-spclient\aspotify\x03com\x00\x00\x1C\x00\x01\xC0\f\x00\x05\x00\x01\x00\x00\x00F\x00\x1A\redge-web-gae2\tdual-gslb\xC0\x1A\xC07\x00\x1C\x00\x01\x00\x00\x00\x1C\x00\x10&\x00\x19\x01\x00\x01\x03\x88\x00\x00\x00\x00\x00\x00\x00\x00",
]
decoded = packets.each_with_object([]) do |pk, arr|
  arr << DNS::Message.decode(pk)
end
puts("\x1B[1FTest 4 - Decode a real message packet - Success")
puts decoded
