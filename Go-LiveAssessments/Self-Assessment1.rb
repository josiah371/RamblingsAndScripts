#!/usr/bin/env ruby

# The MIT License (MIT)
# Copyright (c) 2016 Josiah371 - outofc0ntr0l
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
# associated documentation files (the "Software"), to deal in the Software without restriction, 
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#used for nexpose - duh
require 'nexpose'
#used for connections
require 'socket'
#used for user input
require 'highline/import'
#used for UUID
require 'securerandom'
#used to parse CSV
require 'csv'

include Nexpose
#Set the timeout correctly as some actions take time
module Nexpose
  class APIRequest
    include XMLUtils
    # Execute an API request
		def self.execute(url, req, api_version='1.1', options = {})
		  options = {timeout: 12000000}
		  obj = self.new(req.to_s, url, api_version)
		  obj.execute(options)
		  return obj
		end
	end
end

def check_status(nsc)
	if nsc.session_id
		puts 'Still Logged In'
	else
		nsc.login
	end
end
#functions for user input
def get_user(prompt = 'Username: ')
  ask(prompt) 
end
def get_password(prompt = 'Password: ')
  ask(prompt) { |query| query.echo = false }
end
def get_credid(prompt = 'Please Enter a credential ID Number from above list to use for the scan: ')
  ask(prompt) 
end
def get_scanid(prompt = 'Please Enter a scanner ID Number from above list to use for the scan: ')
  ask(prompt)
end
def get_email(prompt = 'Please Enter an Email Address for the report: ')
  ask(prompt)
end
# Message to users
# I increment the version numbers so if there is an error I know the version number used

##################################################################
# script version
@version = "6"
# Name of team to reach out to if there is an issue
@team_name = "A Team"
# Email of the team 
@team_email = "A-Team@cyberteam.us"
#
# Load Site - This is the site we use to scan all assets from.
# We are not using cross site correlation. If you are using it then this could be
# adjusted to pick the site the asset belongs to to scan it.
# if you are setting up like we have then you want to set the site ID of the site 
# to the below.
@siteIDNum = '603'
# template to use for the scan
@template = 'full-audit-without-web-spider'
# Report ID Name
@report_ID = 'audit-report-TEMPLATE'
#
# get the Username
# I prefer to keep the username in the code as not to give it to 
# everyone so they arent trying to login to the console. I understand that
# someone could get it anyway this is merely out of sight out of mind.
# we have this as acceptable risk. Your org may be different
#
# I also use the version number with the username so they arent using old versions
#
#uncomment this line and comment out the @account below it to ask the user for the username
#leave as is for hard coded username
#@account = get_user
@account = "gl" + "ac" + "co" + "un" + "t" + @version
#
#IP of console
@IP = '10.2.1.3'
###################################################################

puts ""
puts " #########################################################################"
puts " #      Thank you for running the Self Assessment Scan Tool"
puts " # To run the tool please ensure you are connected to the Network"
puts " # If you have problems with the tool please contact: #{@team_name}"
puts " #   #{@team_email} Version v.#{@version}"
puts " #########################################################################"
nsc = nil


# Get the password from the user to build the connection string
@password = get_password
# Build the connection string and set the console connection
nsc = Connection.new(@IP, @account, @password)
#login to the console
begin
	# Notify the user of the login
	puts "Logging in"
	#login to the console
	nsc.login()
	#set the logout command if the script exits
	at_exit { nsc.logout }
	#check for a valid session
	if nsc.session_id.nil? then
	 #If there is no valid session exit out
	 puts "No Valid Session ID: password invalid or account is locked"
	 exit()
	 else
	 #otherwise write the session ID to the screen
	 puts "Your Session ID is: #{nsc.session_id}"
	end
rescue
	#on any error exit the script
	puts ">>>>> Login Failed!"
	exit()
end

# get the hostname and IP address of the asset -
# sometimes in multi IP enviornments this can have some issues
# could ask the user for IP (we chose not to as we dont want them 
# scanning other assets)
host = `hostname`.strip
ip_address = Socket.ip_address_list.find { |ai| ai.ipv4? && !ai.ipv4_loopback? }.ip_address
puts "The IP that will be scanned is: #{ip_address}"

# This is used to attempt to match the domain of the host to the domain creds in Nexpose.
# Any cred can be used by ID but since we are using this script primarily for windows servers
# they typically exist in the domain. If not and there is a staging area etc then you might 
# want to remove the recomended creds all together. 
#
# set a variable to hold the recomended domain for the creds
recommend_domain = ""

#get the fully qualified domain name and split out the domain portion of it
fqdn = Socket.gethostbyname(Socket.gethostname).first
if fqdn != nil
	loc = fqdn.split(".")
	puts "Domain: #{loc[1]}"
else
	#if there is no domain just add bogus data so there is no match
	fqdn = "zzz"
end

# This will list out the credentials list from the console so the user can select 
# which creds they want to use to scan the asset. We have multiple domains so if you 
# dont then you may want to remove this. Also you may want to set these specifically
# to a set of creds maybe a staged enviornment etc.
# list all the shared credentials
#
# Any site specific creds get tested by default.
begin
	# gets a list of the shared creds available to use
	current_creds = nsc.shared_credentials
	# sort them by name
	tcc = current_creds.sort_by do |x|
	 x.name
	end
	rescue => e
	# if session persists but account is locked
	# or if there is an error
	puts ">>>>> Account is most likley locked out!"
	puts ">>>>> Enter any key to exit"
	gets
	exit()
end 
#
# Logged in 
#
# check to make sure still logged in.
puts "Logged in"
# set the found to false as this will let us know if there is a recommended credential
found = false
val2 = "Recommended Cred: Not Found"
# So to limit the credentials I am only showing CIFS creds this way there is a clean list targeting the 
# windows credentials.
# this also goes and recomends a credential to the user to use based on a match
#
tcc.each do |cc|
    if cc.service == 'cifs' and cc.domain != ""
		puts "\tCredential ID: #{cc.id} - Domain: #{cc.name}"
		val1 = loc[1]
		if val1== nil
			val1 == ""
		else
			val1 = val1.downcase
		end
		if (cc.domain.downcase.include? val1)&& found == false
			val2 = "Recommended cred is: #{cc.id} Domain: #{cc.domain} "
			found = true
		end
    end
end
# this is a recommentation to use the cred and lets the user know which one is recommended.
	puts "///////////////////////////////////////////////////////////////////"
	puts "#{val2}"
	puts "///////////////////////////////////////////////////////////////////"
puts ""

# Get the cred ID that the user selected and store it for use.
begin
   @cid = get_credid
end while tcc.include? @cid

# Similar to the other engine list and credentials try to recommend an engine 
# based on a match of the name. If there is a match recommend that engine 
# otherwise let them pick an engine.
#
# needs to select location.
current_engines = nsc.list_engines
tce = current_engines.sort_by do |x|
 x.name
end
val2 = "Recommended Engine: Not Found - Please pick closest location from list! "
tce.each do |ce|
        puts "\tEngine ID: #{ce.id} - Engine Name: #{ce.name}"
		if ce.name.downcase.include? loc[1].downcase
			val2 = "Recommended scan Engine: #{ce.id} Name: #{ce.name} "
			found = true
		end
end
	puts "///////////////////////////////////////////////////////////////////"
	puts "#{val2}"
	puts "///////////////////////////////////////////////////////////////////"
puts ""
# get the scan engine id
begin
   @sid = get_scanid
end while tce.include? @sid


# get the site loaded up
site = Site.load(nsc, @siteIDNum)

# Make sure the credentials selected are assigned to the site.
# Add cred to site
cred = SharedCredential.load(nsc, @cid)
cred.sites << site.id
cred.save(nsc)

# Setup scan with IP
ip_to_scan = [ip_address]

# Scan this IP with Scan engine and template
scan = nsc.scan_assets_with_template_and_engine(site.id, ip_to_scan, @template, @sid)

# Scan the site after creating it
# Sometimes this can take a bit.
puts "Scanning Asset this could take up to 20 mins. Please leave this running"
begin
  sleep(30)
  puts "Scanning Please Wait ..."
  status = nsc.scan_status(scan)
end while status != Scan::Status::FINISHED

#check the status after scan
check_status(nsc)

#get the asset Info for reporting
asset_id = Criterion.new(Search::Field::IP_RANGE, Search::Operator::IN, [ip_address,ip_address])
siteinfo = Criterion.new(Search::Field::SITE_ID, Search::Operator::IN, site.id)
criteria = Criteria.new([asset_id, siteinfo])
found_asset = nsc.search(criteria)

if found_asset[0].id == nil || found_asset.count > 1 then
	puts "There was no asset found for reporting or there was more than one found." 
	puts "This can happen for multiple reasons. Please try again or contact Threat Management"
	gets 
	exit()
end

# After a scan is run Query the db and find out if
# a good credentialed scan happened 
# Check Authentication
# Build query to check authentication
# only getting records with a 1 meaning "full creds"
query = "SELECT DISTINCT *
FROM dim_asset_operating_system
where certainty = 1 and asset_id = #{found_asset[0].id}"

# Building report to run the authentication query
report_config = Nexpose::AdhocReportConfig.new(nil, 'sql')
report_config.add_filter('version', '2.0.2')
report_config.add_filter('query', query)
report_config.add_filter('device', found_asset[0].id)
puts "Checking Authentication, Please wait ..."
puts "This can take 5-10 minutes there will be no notifications..."

#check the status of login after query report
check_status(nsc)

# Run the report
report_output = report_config.generate(nsc)
# capture the output of the authentication report
csv_output = CSV.parse(report_output, {:headers => :first_row} )
puts "Records Found: #{csv_output.count}"

# check for the number of records returned
# the report output is csv so we are parsing and looking for at least 1 row
# if credentials were successful, continue
if csv_output.count >= 1 then
	puts "Authentication Successful! :)"
	# get an email to send the vuln report to a user
	@email = get_email
	while (@email == nil) || (@email.length < 6 || @email.length > 200) do
		puts "Invalid Email Please Try Again"
		@email = get_email
	end
	#get a random UUID for the report name
	reportName = host + '-' + SecureRandom.uuid
	puts "Scan Complete ... Generating Report ..."
	#run report
	# setup the report to be run and delivered via email
	config = ReportConfig.new(reportName, @report_ID, 'pdf')
	em = Email.new(to_all_authorized=false, send_to_owner_as=nil, send_to_acl_as=nil, send_as="zip")
	del = Delivery.new(false, nil, em)
	config.delivery = del
	config.delivery.email.recipients = [@email]
	config.filters = []
	config.add_filter('vuln-status', 'vulnerable-exploited')
	config.add_filter('vuln-status', 'vulnerable-version')
	config.add_filter('scan', 'last')
	config.add_filter('device', found_asset[0].id)
	report_id = config.save(nsc, true)
	#generate the report
	begin
	  puts "Please Wait Generating Report ..."
	  status = nsc.last_report(report_id).status
	  puts status
	  sleep(20)
	end while status == "Started"

	puts "Please wait cleaning up..."
	sleep(5)
	#delete Report
	config.delete(nsc)

	puts ""
	puts "#######################ATTENTION##############################"
	puts "# This does not indicate that the assessment is complete."
	puts "# There are many factors to scanning. This is meant to give"
	puts "# You a tool by which to assess the Device prior to"
	puts "# ---- #{@team_name}"
	puts "##############################################################"
	puts " Process Completed...Press Enter"
	gets
else
	puts ""
	puts "#########################ERROR################################"
	puts "# ERROR: Authentication did not succeed on the asset."
	puts "# Please Contact #{@team_name} as there are many factors"
	puts "# to scanning a device."
	puts "# ---- #{@team_name}"
	puts "##############################################################"
	puts " Process Completed...Press Enter"
	gets
end
