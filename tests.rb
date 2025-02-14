#!/bin/env ruby

puts "Test 1 - Load DNS"
require_relative 'tdns'
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


puts "\x1B[1FTest 3 - Encode/Decode - Success"
puts encoded
puts decoded
