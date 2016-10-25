#!/usr/bin/env ruby
require 'nexpose'

include Nexpose

nsc = Connection.new('127.0.0.1', 'user', 'pass')
nsc.login
at_exit { nsc.logout }

# Allow the user to pass in the site ID to the script.
site_id = ARGV[0].to_i

# Write the site configuration to a file.
site = Site.load(nsc, site_id)
File.write('site.xml', site.to_xml)

# Grab scans and sort by scan end time
scans = nsc.site_scan_history(site_id).sort_by { |s| s.end_time }.map { |s| s.scan_id }

# Scan IDs are not guaranteed to be in order, so use a proxy number to order them.
i = 0
scans.each do |scan_id|
  nsc.export_scan(scan_id, "scan-#{i}.zip")
  i += 1
end
