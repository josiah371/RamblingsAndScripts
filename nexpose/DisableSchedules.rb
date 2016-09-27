#!/usr/bin/env ruby

require 'nexpose'
include Nexpose

#set Connection
nsc = Connection.new('url', 'nxadmin', 'nxpssword')
# Login to NSC and Establish a Session ID
nsc.login
at_exit { nsc.logout }

# Check Session ID
if nsc.session_id
    puts 'Login Successful'
else
    puts 'Login Failure'
    exit
end
nexS = []
#get a list of Ids
s = nsc.sites
s.each do |i|
        nexS << i.id
end
puts "Total Sites: #{nexS.count}"
puts "Checking each site for a schedule ... "
nexS.each do |cSiteId|
    #Load the site
    puts "Loading Site: #{cSiteId}"
    tmpSiteId = Site.load(nsc, cSiteId)
    #check for schedules
    puts "#{tmpSiteId.schedules.count} Schedules Found"
    puts "Updating Schedules..."
    if tmpSiteId.schedules.count > 1
        #loop through and disable schedules
        tmpSiteId.schedules.each do |tmpSiteSchedule|
        #get the schedule 1 by 1 and disable
                tmpSiteSchedule.enabled = false
                begin
                tmpSiteId.save(nsc)

                rescue => e
                #todo write errors to log
                end
        end
    elsif tmpSiteId.schedules.count > 0
        #disable the 1 site
        tmpSiteId.schedules[0].enabled = false
        begin
                tmpSiteId.save(nsc)

        rescue => e
        #todo write errors to log
        end
    end
end



