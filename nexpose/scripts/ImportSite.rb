#!/usr/bin/evn ruby  
require 'nexpose'  
  
include Nexpose  
  
nsc = Connection.new('reporting-console', 'nxadmin', 'someOtherSecretPassword')  
nsc.login  
at_exit { nsc.logout }  
  
site_xml = File.read('site.xml')  
xml = REXML::Document.new(site_xml)  
site = Site.parse(xml)  
site.id = -1  
# Set to use the local scan engine.  
site.engine = nsc.engines.find { |e| e.name == 'Local scan engine' }.id  
site_id = site.save(nsc)  
  
# Import scans by numerical ordering  
scans = Dir.glob('scan-*.zip').map { |s| s.gsub(/scan-/, '').gsub(/\.zip/, '').to_i }.sort  
scans.each do |scan|  
  zip = "scan-#{scan}.zip"  
  puts "Importing #{zip}"  
  nsc.import_scan(site.id, zip)  
  # Poll until scan is complete before attempting to import the next scan.  
  last_scan = nsc.site_scan_history(site.id).max_by { |s| s.start_time }.scan_id  
  while (nsc.scan_status(last_scan) == 'running')  
    sleep 10  
  end  
  puts "Integration of #{zip} complete"  
end  
