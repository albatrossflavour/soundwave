#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'open3'
require 'puppet'

def run_soundwave
  cmd = %w[systemctl start soundwave]
  _, stderr, status = Open3.capture3(*cmd)
  raise Puppet::Error, "Unable to execute soundwave.service. stderr: #{stderr}" if status != 0

  cmd = %w[journalctl -u soundwave -n30 --no-pager]
  stdout, stderr, status = Open3.capture3(*cmd)
  raise Puppet::Error, "Unable to execute soundwave.service. stderr: #{stderr}" if status != 0

  { status: stdout.strip }
end

begin
  result = run_soundwave
  puts result.to_json
  exit 0
rescue Puppet::Error => e
  puts({ status: 'failure', error: e.message }.to_json)
  exit 1
end
