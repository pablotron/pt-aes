#!/usr/bin/env ruby

# generate MIX_LUT for MixColumns step of AES round

puts (256 * 3).times.map { |i|
  v = i & 0x000000ff
  case i >> 8
  when 0
    v
  when 1
    (v << 1) ^ ((v & 0x80) ? 0x1b : 0)
  when 2
    (v << 1) ^ ((v & 0x80) ? 0x1b : 0) ^ v
  end
}.map { |v|
  '0x%02x' % [v & 0xff]
}.each_slice(8).map { |row|
  row.join(', ')
}.join(",\n")
