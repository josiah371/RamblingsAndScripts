Go-Live assessments Scripts and tools
======================================

-Powershell Script
*Registry Checks
*Group Policy Checks
*Files System Checks

Ruby Script
-Preqs
	*Ruby (https://www.ruby-lang.org/en/)
	*Ruby Gems (https://rubygems.org/)
	*Nexpose-client Gem (https://rubygems.org/gems/nexpose)
	*ocra Gem (https://rubygems.org/gems/ocra)
	*An account in Nexpose that can modify 1 site and launch a scan
	*Report format you want sent out after a run (we use a csv)
	*A site that will be used for scanning the assets (load the scope of assets into the site that you want to scan we use ranges of our enviornment)
	
	
-Customize the script for your baseline and enviornment
	*Add Console IP/hostname
	*Add User Account
	*Add SiteID
	*Add ReportID
	
-Use ocra to complie it (e.g. ruby ocra filename.rb)
(it will run you through the script once and compile with same name as script)
ocra scriptname.rb
	
-Order of Operations
	*Scan
	*Check Authentication
	*Generate a report
	
Powershell Script


******* To Run *******

Open powershell as Admin
cd $env:userprofile\Desktop
.\Test-GoLive_v1_X.ps1
Open folder .\Desktop\go-live\index.htm Review Data

 

