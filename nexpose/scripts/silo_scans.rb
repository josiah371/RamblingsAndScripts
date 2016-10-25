#!/usr/bin/env ruby

require 'nexpose'
require 'yaml'
require 'csv'

#set the silo ID
siloID = nil

## Input CSV File that contains SiloIDs
silo_file = 'silo_list.csv'

## method to read and parse a YAML configuration file and return a openstruct
def getConfig( configFilename = "config.yml")
    ## read the YAML config file
    config = OpenStruct.new( YAML.load_file( configFilename ) )

    return config
end
#Get the site name
def getSite(nsc, siteID)
    thisSite = Nexpose::Site.load(nsc, siteID)
    return thisSite
end
# read the csv file
# I left the yml data in the file you could use if for username password uri etc if they are all the same
CSV.foreach(silo_file, {:headers => true}) do |row|
    # Skip any rows that have Empty column entries for silos
    next if row['silo'].nil? || row['take'] || row['uri'].nil? || row['username'].nil? || row['password']
        #

    #get the config options
    $CONFIG = getConfig()

    # Create a new Nexpose::Connection on the default port
    #nsc = Nexpose::Connection.from_uri( $CONFIG.nexposeURI, $CONFIG.nexposeUser, $CONFIG.nexposePassword, row['silo'] )
    nsc = Nexpose::Connection.from_uri( row['uri'], row['username'], row['password'], row['silo'] )

    # Login to NSC and Establish a Session ID
    nsc.login

    # Check Session ID
    if nsc.session_id
        puts 'Login Successful'
    else
        puts 'Login Failure'
    end

    thisSite = nil
    #Past Scans (for entire Console)
    pastScans = ""
    #take the latest 10 scans
    ps = nsc.past_scans(row['take'])
    puts "\nPast Scans: #{ps.count}\n"
    ps.each do |pastScan|
        puts "Site Name: #{getSite(nsc, pastScan.site_id).name},Scan Start:, #{pastScan.start_time}, Scan End: #{pastScan.end_time}, \nEngine ID: #{pastScan.id}, Status: #{pastScan.status}, Duration: #{(pastScan.duration/1000)/60}min, Assets Scanned: #{pastScan.assets}"
    end

    # Current Scans
    cs = ""
    cs = nsc.scan_activity
    puts "\nScans Running: #{cs.count}\n"
    cs.each do |thisScan|
        puts "Site ID: #{thisScan.site_id}, Site Name: #{getSite(nsc, thisScan.site_id).name},  Scan ID: #{thisScan.scan_id}, Engine ID: #{thisScan.engine_id} Status: #{thisScan.status}"
    end
    puts ""
    # Logout
    logout_success = nsc.logout
end
                                