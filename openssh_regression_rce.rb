##
# This module requires Metasploit Framework and Ruby
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::SSH

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'OpenSSH sshd Regression RCE (CVE-2024-6387)',
      'Description'    => %q{
        This module exploits a regression in OpenSSH's sshd (CVE-2024-6387), introduced in OpenSSH 8.5p1 and
        patched in 9.8p1. The vulnerability allows unauthenticated remote attackers to execute arbitrary code
        as root by triggering a signal handler race condition during unauthenticated SSH handshake.

        This module currently performs version checking and fingerprinting.
      },
      'Author'         => [ 'Yon' ],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['CVE', '2024-6387'],
        ['URL', 'https://www.qualys.com/2024/06/26/cve-2024-6387/regresshion-advisory.txt'],
        ['URL', 'https://blog.qualys.com/vulnerabilities-threat-research/2024/06/26/cve-2024-6387-a-critical-openssh-server-vulnerability']
      ],
      'DisclosureDate' => '2024-06-26',
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      'Targets'        => [['Automatic', {}]],
      'DefaultTarget'  => 0,
      'DefaultOptions' => {
        'RPORT' => 22,
        'PAYLOAD' => 'cmd/unix/reverse_netcat'
      },
      'Privileged'     => true
    ))

    register_options([
      Opt::RPORT(22),
      OptString.new('SSH_BANNER', [false, 'Expected vulnerable banner substring', 'OpenSSH_8.5']),
    ])
  end

  def check
    connect
    banner = sock.get_once(-1, 5)
    disconnect

    if banner && banner.include?(datastore['SSH_BANNER'])
      print_good("Target appears to be running vulnerable version: #{banner.strip}")
      return Exploit::CheckCode::Appears
    elsif banner && banner.include?("OpenSSH_9.8")
      print_status("Target appears patched: #{banner.strip}")
      return Exploit::CheckCode::Safe
    else
      print_status("Target SSH banner: #{banner.strip}") if banner
      return Exploit::CheckCode::Unknown
    end
  end

  def exploit
    print_status("No working exploit for CVE-2024-6387 available. This is a detection module template.")
    fail_with(Failure::NoTarget, "Manual exploitation or custom payload may be required.")
  end
end
