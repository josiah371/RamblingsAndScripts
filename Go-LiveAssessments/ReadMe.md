Go-Live assessments Scripts and tools
======================================

Powershell Script:

	1. Registry Checks
	2. Group Policy Checks
	3. Files System Checks

Ruby Script
Preqs:

	1. Ruby (https://www.ruby-lang.org/en/)
	2. Ruby Gems (https://rubygems.org/)
	3. Nexpose-client Gem (https://ru. ruby ocra filename.rb)
	(it will run you through the script once and compile with same name as script)
	syntax - ocra scriptname.rb
	4. ocra Gem (https://rubygems.org/gems/ocra)
	5. An account in Nexpose that can modify 1 site and launch a scan
	6. Report format you want sent out after a run (we use a csv)
	7. A site that will be used for scanning the assets (load the scope of assets 
	into the site that you want to scan we use ranges of our enviornment)
	
	
	
-Order of Operations

	*Scan
	*Check Authentication
	*Generate a report
	
Powershell Script


******* To Run *******

Open powershell as Adminbygems.org/gems/nexpose)
	
	
	
Customize the script for your baseline and enviornment

	*Add Console IP/hostname
	*Add User Account
	*Add SiteID
	*Add ReportID
	
-Use ocra to complie it (e.g
cd $env:userprofile\Desktop
.\Test-GoLive_v1_X.ps1
Open folder .\Desktop\go-live\index.htm Review Data

 

