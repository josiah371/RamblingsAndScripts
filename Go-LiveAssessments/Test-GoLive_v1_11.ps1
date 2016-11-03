{
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
}

#Powershell Checks
#
#SMTP server to send zip files to 
$SMTPServer = "<Your SMTP Server>"
#script Version
$version = "1.11"
#set execution policy for the Process
$ex_pol = Get-ExecutionPolicy
if ($ex_pol -eq "RemoteSigned")
{
    Write-Host -BackgroundColor black "Setting Execution Policy for this Script"
    Write-Host  -BackgroundColor black "Execution Policy: "
    Write-Host -BackgroundColor DarkYellow  $ex_pol

}else
{
    Write-Warning "We need to set the script permissions to RemoteSigned"
    try{
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    }
    catch
    {
    }
}


# checks if a string contains a value results and returns a message
function Check-Contains
{
[CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='String to Check')]
    [string[]]$stringToCheck,
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='Contains Value')]
    [string[]]$containsValue
  )
  
  if ($stringToCheck -match $containsValue)
  {
    $true
  }
  else
  {
    $false
  }
}



# compares two results and returns a message
function write-boolResult
{
[CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='Test Against Value')]
    [Alias('testValue1')]
    [string[]]$_val1,
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='Value to Test')]
    [Alias('testValue2')]
    [string[]]$_Val2,
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='Message to Write')]
    [Alias('Message')]
    [string[]]$_Message
  )
  if ($_va1 -eq $_val2)
  {
    Write-Host -foregroundColor Green "`t$($_Message):$_val2 (Passed)"
  }
  else
  {
   Write-Host -foregroundColor Red "`t$($_Message):$_val2 (Failed)"
  }
}
#Returns the Registry Key
function Get-RegKeyVal
  {
 
 [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='What Registry Key to Lookup?')]
    [Alias('key')]
    [string[]]$RegKey
  )
 try{
 Return (New-Object -ComObject WScript.Shell).RegRead("$RegKey")
 }
 catch [System.Exception]
 {

 Return "Error getting key: $($_.Exception.message)" 
 }

}
#Gets a Policy item (auditpol)
function Get-PolicySubCategory
{
[CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True,
      HelpMessage='What Secuirty Policy to Lookup?')]
    [Alias('key')]
    [string[]]$PolVal
  )
  $len = ($PolVal[0].Length) + 2
$(Auditpol /get /subcategory:"$PolVal")[4].tostring().substring($len).trim()
}

#check admin
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
           [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
      Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
       Break
   }

#get OS information
try{
if (!(test-path "$env:userprofile\Desktop\Go-Live\")) {mkdir "$env:userprofile\Desktop\Go-Live"}

Write-Host -BackgroundColor black "Getting Script Version"
Write-host "`tScript Version:$version"

# Get OS information
"Checking For Proper OS Settings" > $env:userprofile\Desktop\Go-Live\OS.html
$info = Get-WMIObject Win32_OperatingSystem -ComputerName $env:COMPUTERNAME |select Caption,OSArchitecture,ServicePackMajorVersion

"<Title>Proper OS</Title>
<body><p>OS Version: $($info.Caption)</p>
<p>Architecture: $($info.OSArchitecture)</p>
<p>Service Pack: $($info.ServicePackMajorVersion)</p></body>
<p>Build Version: $($OSVersion)</p>
<p>Script Version: $($version)" >> $env:userprofile\Desktop\Go-Live\OS.html
}
catch
{ Write-Host -ForegroundColor Red "Error getting OS information"
"Error getting OS information" >> $env:userprofile\Desktop\Go-Live\OS.html}

#get local time and domain time and compare them
try{
Write-Host -BackgroundColor black "Server is syncing or in sync with DC time."
#Local Computer Time
"Computer Time is:" | Out-File "$env:userprofile\Desktop\Go-Live\time.txt"
$ct = [string](net time \\$env:COMPUTERNAME) 
$ct | Out-File "$env:userprofile\Desktop\Go-Live\time.txt" -Append
$ctm = $ct -split(' ')
$tm = ""
#Domain Controller Time
 "Domain Controller Time is:" | Out-File "$env:userprofile\Desktop\Go-Live\time.txt" -Append
     try
    {
        $d = Get-WmiObject Win32_ComputerSystem
                $ErrorActionPreference = 'Stop'
        $dt = [string](net time /domain:$($d.domain))
        $dt  | Out-File "$env:userprofile\Desktop\Go-Live\time.txt" -Append
        $tm = $dt -split (' ')
    }
    catch [System.Management.Automation.RemoteException]
    {
        $e = $_.Exception.message
    }
    if ($tm[6].Substring(0,4) -eq $ctm[6].Substring(0,4)) {
    "`nTime is synced (Passed)" | Out-File "$env:userprofile\Desktop\Go-Live\time.txt" -Append
    Write-Host -ForegroundColor Green "`tTime is synced (Passed)"}
    else {
    "`nTime is not synced (Failed)"| Out-File "$env:userprofile\Desktop\Go-Live\time.txt" -Append
    Write-Host -ForegroundColor Red "`tTime is not synced (Failed)"}
    if ($dt.count -eq 0)
    {
        $out = "No Access to domain time"
        $out | Out-File "$env:userprofile\Desktop\Go-Live\time.txt" -Append
    }
}
catch{ }

#Check for SCCM Monitoring
#Make sure the SCCM client is pointing to our SCCM Server
$SCCMServerName = 'google.com'
try
{
Write-Host -BackgroundColor black "Checking For SCCM" 
"Checking For SCCM" > $env:userprofile\Desktop\Go-Live\SCCM.txt
    $lmp = Get-RegKeyVal -RegKey "HKLM\SOFTWARE\Microsoft\CCMSetup\LastValidMP"
    if ($lmp.contains($dn) -or $lmp.contains($SCCMServerName))
    { 
    "`tSyncing to: $lmp : (Passed)" >> $env:userprofile\Desktop\Go-Live\SCCM.txt
    Write-Host -ForegroundColor Green "`tSyncing to: $lmp : (Passed)" }
    else {    
    "`tSyncing to: $lmp : (Failed)" >> $env:userprofile\Desktop\Go-Live\SCCM.txt
    Write-Host -ForegroundColor Red "`tSyncing to: $lmp : (Failed)" }
}
catch
{ Write-Host -ForegroundColor Red "No Key Found Failed due to an Error"}

#check password data
#Make sure to set these for your enviornment
$ForceUserLogoff = 'Never'
$MinPasswordAge = '4'
$MaxPasswordAge = '90'
$MinPasswordLen = '10'
$PasswordHistory = '8'
$PasswordLockout = '3'
$LockoutDurration = 'Never'
$LockoutWindown = '60'
###########################################
try{
Write-Host -BackgroundColor black "Account Information"
$na = net accounts 
"Account Information" > "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
if ($na[0].contains($ForceUserLogoff))
{ "`t$($na[0]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[0]) (Passed)"}
else
{"`t$($na[0]) (Failed) Should be $ForceUserLogoff" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[0]) (Failed) Should be Never"}

if ($na[1].Contains($MinPasswordAge))
{"`t$($na[1]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[1]) (Passed)"}
else
{"`t$($na[1]) (Failed) Should be $MinPasswordAge" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[1]) (Failed) Should be 4"}
#password change
if ($na[2].Contains($MaxPasswordAge))
{"`t$($na[2]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[2]) (Passed)"}
else
{"`t$($na[2]) (Failed) Should be $MaxPasswordAge" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[2]) (Failed) Should be 90"}
#password Length
if ($na[3].Contains($MinPasswordLen))
{ "`t$($na[3]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[3]) (Passed)"}
else
{ "`t$($na[3]) (Failed) Should be $MinPasswordLen" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[3]) (Failed) Should be 10"}
#password length
if ($na[4].Contains($PasswordHistory))
{"`t$($na[4]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[4]) (Passed)"}
else
{"`t$($na[4]) (Failed) Should be $PasswordHistory" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[4]) (Failed) Should be 8"}
#lockout count
if ($na[5].Contains($PasswordLockout))
{"`t$($na[5]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[5]) (Passed)"}
else
{"`t$($na[5]) (Failed) Should be $PasswordLockout" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[5]) (Failed) Should be 3"}
#Manual UNLOCK REQUIRED do allow an auto unlock
if ($na[6].Contains($LockoutDurration))
{"`t$($na[6]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[6]) (Passed)"}
else
{"`t$($na[6]) (Failed) Should be $lockoutDuration" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[6]) (Failed) Should be $lockoutDuration"}
#
if ($na[7].Contains($LockoutWindown))
{"`t$($na[7]) (Passed)" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Green "`t$($na[7]) (Passed)"}
else
{"`t$($na[7]) (Failed) Should be $LockoutWindown" >> "$env:userprofile\Desktop\Go-Live\netAccounts.txt"
Write-Host -foregroundColor Red "`t$($na[7]) (Failed) Should be $LockoutWindown"}

Write-Host -foregroundColor Yellow "`t$($na[8]) (N/A)"
}
catch
{ Write-Host -ForegroundColor Red "Password Data Checks Failed due to an Error" }

#https://technet.microsoft.com/en-us/library/jj852207(v=ws.11).aspx
Write-Host -BackgroundColor black "NTLMv2"
"NTLM Settings" > "$env:userprofile\Desktop\Go-Live\NTLM.txt"
$LMLevel = Get-RegKeyVal "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LMCompatibilityLevel"
if ($LMLevel -eq 3 -or $LMLevel -eq 5)
{"`t NTLM Settings (Passed)" >> "$env:userprofile\Desktop\Go-Live\NTLM.txt"
Write-Host -foregroundColor Green "`tNTLMv2 ($LMLevel) Turned On (Passed)"
}else{
"`t NTLM Settings $LMLevel (Failed)" >> "$env:userprofile\Desktop\Go-Live\NTLM.txt"
Write-Host -foregroundColor Red "`t$($na[7]) (Failed) NTMLv2 Should be 3 or 5"}

#check for the correct banner installed
#Set Banner for your Organization
$banner = "This information system, its associated sub-systems, and the content contained within are CONFIDENTIAL and PROPRIETARY INFORMATION, and remain the sole and exclusive property of this company. This information system may be accessed and used by authorized personnel only. Authorized users may only perform authorized activities and may not exceed the limits of such authorization. Use and/or disclosure of information contained in this information system for any unauthorized use is *STRICTLY PROHIBITED*. All activities on this information system are subject to monitoring, recording, and review at any time. Users should assume no expectation of privacy. Intentional misuse of this information system may result in disciplinary or legal action taken by this company. Continued use of this information system represents that you are an authorized user and agree to the terms stated in this warning."
#######################################
try{
Write-Host -BackgroundColor black "Check Login Banner"
"Login Banner should be: " | Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt"

$banner | Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt" -Append
"`n"| Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt" -Append
"`nLogin Banner is: " | Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt" -Append
$computerBanner = Get-RegKeyVal "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext"
$computerBanner | Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt" -Append

if ($banner -eq $computerBanner) {
write-host -ForegroundColor Green "`tBanner Text: (Passed)" 
"`nBanner Text: (Passed)"| Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt" -Append}
else {
    write-host -ForegroundColor Red "`tBanner Text: (Failed)" 
    "`nBanner Text: (Failed)" | Out-File "$env:userprofile\Desktop\Go-Live\LoginBanner.txt" -Append} 
}
catch
{ Write-Host -ForegroundColor Red "Banner Check Failed due to an Error" }

#Check AV
#check for Symantec Version and Server IP
try{
Write-Host -BackgroundColor black "Symantec Server IP and Version"
#get the IP of the last sync server
$val = Get-RegKeyVal "HKLM\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\public-opstate\LastServerIp"
"Symantec Server IP and Version" > "$env:userprofile\Desktop\Go-Live\symantec.txt"
"LastServerIp" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
$val >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
$result = switch ($val)
{
# put your sep server info here
"10.10.47.66" {"Linked to <put sep server name here>"}
"10.10.47.67" {"Linked to <put sep server name here>"}
default{"Symantec Connected to Unknown Server - Not Valid"}
}
"`n*******************************" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
$result >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
"`n*******************************`n" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
"`nSymantec Version`n" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
#check for Virus Date Information
$val = Get-RegKeyVal "HKLM\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\public-opstate\LatestVirusDefsDate"
"Virus Defs Date" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
$df = get-date -f yyyy-MM-dd
if ($val -eq $df)
{ Write-Host -ForegroundColor Green "`tDefinition Date: $val (Passed)"
" Definition Date: $val (Passed)" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"}
else
{Write-Host -ForegroundColor Red "`tDefinition Date: $val (failed)"
"Definition Date: $val (Failed)" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"}
# check for the version
$a = Get-RegKeyVal "HKEY_LOCAL_MACHINE\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\PRODUCTVERSION"
"`nPRODUCTVERSION" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
$a >> "$env:userprofile\Desktop\Go-Live\symantec.txt"

if ($result.contains('Linked')) { 
"`n$result (Passed)" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
Write-Host -ForegroundColor Green "`t$result (Passed)"}
else{
"`n$result (Failed)" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
Write-Host -ForegroundColor Red "`t$result (Failed)"}
# Here is the latest two versions of SEP 
if ($a.Contains('12.1.7')) { 
"$a (Passed)" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
Write-Host -ForegroundColor Green "`t$a (Passed)"}
else{
"$a (Failed)" >> "$env:userprofile\Desktop\Go-Live\symantec.txt"
Write-Host -ForegroundColor Red "`t$a (Failed)"}
} 
catch
{ Write-Host -ForegroundColor Red "Symantec Check Failed due to an Error" }

#check for Mcafee
try
{
Write-Host -BackgroundColor black "Mcafee Version"

    "`n mcAfee Product:" > "$env:userprofile\Desktop\Go-Live\mcafee.txt"
    $val1 = try {Get-RegKeyVal "HKLM\SOFTWARE\Wow6432Node\McAfee\DesktopProtection\Product"} 
    catch {
    write-Host -ForegroundColor Yellow "`tNo Key found for McAfee Product"
    "`tNo Key found for McAfee Product" >> "$env:userprofile\Desktop\Go-Live\mcafee.txt" }
    
    "`n mcAfee Dat Date:" >> "$env:userprofile\Desktop\Go-Live\mcafee.txt"
    $val2 = try {Get-RegKeyVal "HKLM\SOFTWARE\Wow6432Node\McAfee\AVEngine\AVDatDate"} 
    catch {
    write-Host -ForegroundColor Yellow "`tNo Key found for McAfee AV Date"
    "`tNo Key found for McAfee AV Date" >> "$env:userprofile\Desktop\Go-Live\mcafee.txt" }
    
   "`n mcAfee Dat Number:" >> "$env:userprofile\Desktop\Go-Live\mcafee.txt"
   $val3 = try {Get-RegKeyVal "HKLM\SOFTWARE\Wow6432Node\McAfee\AVEngine\AVDatVersion"} 
    catch {
    write-Host -ForegroundColor Yellow "`tNo Key found for McAfee AV Dat Version"
    "`tNo Key found for McAfee AV Dat Version" >> "$env:userprofile\Desktop\Go-Live\mcafee.txt" }
    }
catch
{ Write-Host -ForegroundColor Red "McAfee Check Failed due to an Error" }

#Check for SCOM
try{

Write-Host -BackgroundColor black "Checking SCOM Installed and Syncing..." 
"Checking SCOM Installed and Syncing..." > $env:userprofile\Desktop\Go-Live\SCOM.txt

#SCOM version is 7.1 if you are using a diggerent scom then you should change this
$av = Get-RegKeyVal -RegKey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup\AgentVersion"
if ($av.contains('7.1') -and $($na[8]).Contains('SERVER'))
{    
"`tSCOM Version: $av : (Passed)" >> $env:userprofile\Desktop\Go-Live\SCOM.txt
Write-Host -ForegroundColor Green "`tSCOM Version: $av : (Passed)" }
elseif ($($na[8]).Contains('WORKSTATION')) {    
"`tSCOM not required Computer Role is: WORKSTATION : (N/A)"  >> $env:userprofile\Desktop\Go-Live\SCOM.txt
Write-Host -ForegroundColor Green "`tSCOM not required Computer Role is: WORKSTATION : (N/A)" }
else {  
"`tSCOM not Current Version or Installed: $lmp : (Failed)"  >> $env:userprofile\Desktop\Go-Live\SCOM.txt
Write-Host -ForegroundColor Red "`tSCOM not Current Version or Installed: $lmp : (Failed)" }
}
catch
{ 
 "No Key Found - this is okay if WORKSTATION ROLE: $($na[8])"  >> $env:userprofile\Desktop\Go-Live\SCOM.txt
Write-Host -ForegroundColor Red "No Key Found - this is okay if WORKSTATION ROLE: $($na[8])"}



#Check for the Log File Sizes checking for 500MB that is the prefered minumum log size
try{
Write-Host -BackgroundColor black "Checking Log File Sizes..."
"Log File Sizes:" > $env:userprofile\Desktop\Go-Live\Logs.txt
$aMApp = Get-RegKeyVal "HKLM\SYSTEM\ControlSet001\services\eventlog\Application\MaxSize"
$val = ($aMApp)
if ($val -ge 500) {
"`tApplication Log File Size > 500MB: (Passed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Green "`tApplication Log File Size > 500MB: (Passed)"}
else {
"`tApplication Log File Size < 500MB: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Red "`tApplication Log File Size < 500MB: (Failed)"}

$aApp = Get-RegKeyVal -RegKey "HKLM\SYSTEM\ControlSet001\services\eventlog\Application\Retention"
if ($aApp -eq 0 ) { 
"`tApplication Log File Retention: (Passed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Green "`tApplication Log File Retention: (Passed)"}
else { 
"`tApplication Log File Retention: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Red "`tApplication Log File Retention: (Failed)"}

$sMSys = Get-RegKeyVal "HKLM\SYSTEM\ControlSet001\services\eventlog\System\MaxSize"
$val = ($sMSys)
if ($val -ge 500) {
"`tSystem Log File Size < 500MB: (Passed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Green "`tSystem Log File Size > 500MB: (Passed)"}
else {
"`tSystem Log File Size < 500MB: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Red "`tSystem Log File Size < 500MB: (Failed)"}

$aSys = Get-RegKeyVal -RegKey "HKLM\SYSTEM\ControlSet001\services\eventlog\System\Retention"
if ($aSys -eq 0 ) { 
"`tSystem Log File Retention: (Passed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Green "`tSystem Log File Retention: (Passed)"}
else { 
"`tSystem Log File Retention: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Red "`tSystem Log File Retention: (Failed)"}

$sMSec = Get-RegKeyVal "HKLM\SYSTEM\ControlSet001\services\eventlog\Security\MaxSize"
$val = ($sMSec)
if ($val -ge 500) {
"`tSecurity Log File Size > 500MB: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Green "`tSecurity Log File Size > 500MB: (Passed)"}
else {
"`tSecurity Log File Size > 500MB: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Red "`tSecurity Log File Size < 500MB: (Failed)"}

$secRet = Get-RegKeyVal -RegKey "HKLM\SYSTEM\ControlSet001\services\eventlog\Security\Retention"
if ($SecRet -eq 0 ) {
"`tSecurity Log File Retention: (Passed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Green "`tSecurity Log File Retention: (Passed)"}
else {
"`tSecurity Log File Retention: (Failed)" >> $env:userprofile\Desktop\Go-Live\Logs.txt
Write-Host -ForegroundColor Red "`tSecurity Log File Retention: (Failed)"}
}
catch
{ Write-Host -ForegroundColor Red "Log File Check Failed due to an Error" }


#Check Audit Policy
try
{
Write-Host -BackgroundColor black "Checking Windows Advanced Audit Policy" 
$oame = Get-PolicySubCategory -PolVal "Other Account Management Events"
$oale = Get-PolicySubCategory -PolVal "Other Account Logon Events"
$sgm = Get-PolicySubCategory -PolVal "Security Group Management"
$uam = Get-PolicySubCategory -PolVal "User Account Management"
$al = Get-PolicySubCategory -PolVal "Account Lockout"
$lo = Get-PolicySubCategory -PolVal "Logoff"
$lon = Get-PolicySubCategory -PolVal "Logon"
$olle = Get-PolicySubCategory -PolVal "Other Logon/Logoff Events"
$sl = Get-PolicySubCategory -PolVal "Special Logon"
$ssc = Get-PolicySubCategory -PolVal "Security State Change"
$si = Get-PolicySubCategory -PolVal "System Integrity"

"Windows Advanced Auditing Settings-" > $env:userprofile\Desktop\Go-Live\secpol.txt
#check all the values
if ($oame -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Other Account Management Events ($oame): (Passed)"
"`tAudit Other Account Management Events ($oame): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Other Account Management Events ($oame): (Failed)"
"`tAudit Other Account Management Events ($oame): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#Other Account Logon Events
if ($oale -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Other Account Logon Events ($oale): (Passed)"
"`tAudit Other Account Logon Events ($oale): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Other Account Logon Events ($oale): (Failed)"
"`tAudit Other Account Logon Events ($oale): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#Security Group Management
if ($sgm -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Security Group Management ($sgm): (Passed)"
"`tAudit Security Group Management ($sgm): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Security Group Management ($sgm): (Failed)"
"`tAudit Security Group Management ($sgm): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#User Account Management
if ($uam -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit User Account Management ($uam): (Passed)"
"`tAudit User Account Management ($uam): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit User Account Management ($uam): (Failed)"
"`tAudit User Account Management ($uam): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#Audit Account Lockout
if ($al -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Account Lockout ($al): (Passed)"
"`tAudit Account Lockout ($al): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Account Lockout ($al): (Failed)"
"`tAudit Account Lockout ($al): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#lo
if ($lo -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Logoff ($lo): (Passed)"
"`tAudit Logoff ($lo): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Logoff ($lo): (Failed)"
"`tAudit Logoff ($lo): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#lon
if ($lon -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Logon ($lon): (Passed)"
"`tAudit Logon ($lon): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Logon ($lon): (Failed)"
"`tAudit Logon ($lon): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#Other Logon/Logoff Events
if ($olle -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Other Logon/Logoff Events ($olle): (Passed)"
"`tAudit Other Logon/Logoff Events ($olle): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Other Logon/Logoff Events ($olle): (Failed)"
"`tAudit Other Logon/Logoff Events ($olle): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#Special Logon
if ($sl -eq "Success and Failure")
{ write-host -ForegroundColor Green "`tAudit Special Logonn ($sl): (Passed)"
"`tAudit Special Logon ($sl): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Special Logon ($sl): (Failed)"
"`tAudit Special Logon ($sl): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#Security State Change
if ($ssc -match "Success")
{ write-host -ForegroundColor Green "`tAudit Security State Change ($ssc): (Passed)"
"`tAudit Security State Change ($ssc): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit Security State Change ($ssc): (Failed)"
"`tAudit Security State Change ($ssc): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
#System Integrity
if ($si -match "Success")
{ write-host -ForegroundColor Green "`tAudit System Integrity ($si): (Passed)"
"`tAudit System Integrity ($si): (Passed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
else
{ write-host -ForegroundColor Red "`tAudit System Integrity ($si): (Failed)"
"`tAudit System Integrity ($si): (Failed)" >> $env:userprofile\Desktop\Go-Live\secpol.txt}
}
catch
{ Write-Host -ForegroundColor Red "Audit Policy Check Failed due to an Error"}

#Get MRT Version
#https://support.microsoft.com/en-us/kb/891716
#we update this each month with the new GUID
try{
$January2014mrt = '7BC20D37-A4C7-4B84-BA08-8EC32EBF781C'
$February2014mrt = 'FC5CF920-B37A-457B-9AB9-36ECC218A003'
$March2014mrt = '?254C09FA-7763-4C39-8241-76517EF78744'
$April2014mrt = '54788934-6031-4F7A-ACED-5D055175AF71'
$May2014mrt = '91EFE48B-7F85-4A74-9F33-26952DA55C80'
$June2014mrt = '07C5D15E-5547-4A58-A94D-5642040F60A2'
$July2014mrt = '43E0374E-D98E-4266-AB02-AE415EC8E119'
$August2014mrt = '53B5DBC4-54C7-46E4-B056-C6F17947DBDC'
$September2014mrt = '98CB657B-9051-439D-9A5D-8D4EDF851D94'
$October2014mrt = '5612279E-542C-454D-87FE-92E7CBFDCF0F'
$November2014mrt = '7F08663E-6A54-4F86-A6B5-805ADDE50113'
$December2014mrt = '386A84B2-5559-41C1-AC7F-33E0D5DE0DF6'
$January2015mrt = '677022D4-7EC2-4F65-A906-10FD5BBCB34C'
$February2015mrt = '92D72885-37F5-42A2-B199-9DBBEF797448'
$March2015mrt = 'CEF02A7E-71DD-4391-9BF6-BF5DEE8E9173'
$April2015mrt = '7AABE55A-B025-4688-99E9-8C66A2713025'
$May2015mrt = 'F8F85141-8E6C-4FED-8D4A-8CF72D6FBA21'
$June2015mrt = '20DEE2FA-9862-4C40-A1D4-1E13F1B9E8A7'
$July2015mrt = '82835140-FC6B-4E05-A17F-A6B9C5D7F9C7'
$August2015mrt = '74E954EF-6B77-4758-8483-4E0F4D0A73C7'
$September2015mrt = 'BC074C26-D04C-4625-A88C-862601491864'
$October2015mrt = '4C5E10AF-1307-4E66-A279-5877C605EEFB'
$November2015mrt = 'FFF3C6DF-56FD-4A28-AA12-E45C3937AB41'
$December2015mrt = 'EE51DBB1-AE48-4F16-B239-F4EB7B2B5EED'
$January2016mrt = 'ED6134CC-62B9-4514-AC73-07401411E1BE'
$February2016mrt = 'DD51B914-25C9-427C-BEC8-DA8BB2597585'
$March2016mrt = '3AC662F4-BBD5-4771-B2A0-164912094D5D'
$April2016mrt = '6F31010B-5919-41C2-94FB-E71E8EEE9C9A'
$May2016mrt = '156D44C7-D356-4303-B9D2-9B782FE4A304'
$June2016mrt = 'E6F49BC4-1AEA-4648-B235-1F2A069449BF'
$July2016mrt = '34E69BB2-EFA0-4905-B7A9-EFBDBA61647B'
$August2016mrt = '0F13F87E-603E-4964-A9B4-BF923FB27B5D'
$September2016mrt = '2168C094-1DFC-43A9-B58E-EB323313845B'
$October2016mrt = '6AC744F7-F828-4CF8-A405-AA89845B2D98'
$November2016mrt = 'Blank'
$December2016mrt = 'Blank'
$January2017mrt = 'Blank'
$February2017mrt = 'Blank'
$March2017mrt = 'Blank'
$April2017mrt = 'Blank'
$May2017mrt = 'Blank'
$June2017mrt = 'Blank'
$July2017mrt = 'Blank'
$August2017mrt = 'Blank'
$September2017mrt = 'Blank'
$October2017mrt = 'Blank'
$November2017mrt = 'Blank'
$December2017mrt = 'Blank'

Write-Host -BackgroundColor black "MRT Version"
$mrtQuery = Get-RegKeyVal "HKLM\SOFTWARE\Microsoft\RemovalTools\MRT\Version"
$data = $mrtQuery.Trim()
$mrtstatus = switch ($data)
{
    $January2014mrt {'MRT is from January 2014'}
    $February2014mrt {'MRT is from February 2014'}
    $March2014mrt {'MRT is from March 2014'}
    $April2014mrt {'MRT is from April 2014'}
    $May2014mrt {'MRT is from May 2014'}
    $June2014mrt {'MRT is from June 2014'}
    $July2014mrt {'MRT is from July 2014'}
    $August2014mrt {'MRT is from August 2014'}
    $September2014mrt {'MRT is from September 2014'}
    $October2014mrt {'MRT is from October 2014'}
    $November2014mrt {'MRT is from November 2014'}
    $December2014mrt {'MRT is from December 2014'}
    $January2015mrt {'MRT is from January 2015'}
    $February2015mrt {'MRT is from February 2015'}
    $March2015mrt {'MRT is from March 2015'}
    $April2015mrt {'MRT is from April 2015'}
    $May2015mrt {'MRT is from May 2015'}
    $June2015mrt {'MRT is from June 2015'}
    $July2015mrt {'MRT is from July 2015'}
    $August2015mrt {'MRT is from August 2015'}
    $September2015mrt {'MRT is from September 2015'}
    $October2015mrt {'MRT is from October 2015'}
    $November2015mrt {'MRT is from November 2015'}
    $December2015mrt {'MRT is from December 2015'}
    $January2016mrt {'MRT is from January 2016'}
    $February2016mrt {'MRT is from February 2016'}
    $March2016mrt {'MRT is from March 2016'}
    $April2016mrt {'MRT is from April 2016'}
    $May2016mrt {'MRT is from May 2016'}
    $June2016mrt {'MRT is from June 2016'}
    $July2016mrt {'MRT is from July 2016'}
    $August2016mrt {'MRT is from August 2016'}
    $September2016mrt {'MRT is from September 2016'}
    $October2016mrt {'MRT is from October 2016 (Passed)'} #we set passed in the current version we dont use
    $November2016mrt {'MRT is from November 2016'}
    $December2016mrt {'MRT is from December 2016'}

    default {"MRT Not Valid."}
}

#
if ($mrtstatus.Contains('Passed')) { Write-Host -ForegroundColor Green "`t$mrtstatus"} 
else {Write-Host -BackgroundColor Red "`t$mrtstatus (Failed)"}
"MRT Check:" > "$env:userprofile\Desktop\Go-Live\mrt.txt"
"GUID: $(Get-RegKeyVal 'HKLM\SOFTWARE\Microsoft\RemovalTools\MRT\GUID')" >> "$env:userprofile\Desktop\Go-Live\mrt.txt"
"VERSION: $(Get-RegKeyVal 'HKLM\SOFTWARE\Microsoft\RemovalTools\MRT\Version')" >> "$env:userprofile\Desktop\Go-Live\mrt.txt"
$mrtstatus >> "$env:userprofile\Desktop\Go-Live\mrt.txt"
}
catch
{ Write-Host -ForegroundColor Red "MRT Check Failed due to an Error"}

#get Software
try{
Write-Host -BackgroundColor black "Software Installed"
"Software Installed:`n`n" | Out-File "$env:userprofile\Desktop\Go-Live\software.txt"
$software = ""
Try{$Software = Get-WmiObject Win32_InstalledWin32Program | Select-Object Name | Sort-Object Name}
catch{ $Software =  Get-WmiObject Win32_Product | Select-Object Name | Sort-Object Name }
$Software >> "$env:userprofile\Desktop\Go-Live\software.txt"
Write-Host -ForegroundColor Yellow "`tSoftware List Review Required"
}
catch
{ Write-Host -ForegroundColor Red "Software ennumeration failed due to an Error"}

#EMET
try
{
$emet = $false
ForEach($s in $Software) { If ($s.Name -contains  "EMET 5.5") {
Write-Host -ForegroundColor Green "`tFound $($s.name) Installed (Passed)"
$emet = $true}}
if ($emet -eq $false){Write-Host -ForegroundColor Red "`tEMET 5.5 Not Installed (Failed)"}
}
catch
{ Write-Host -ForegroundColor Red "EMET Check Failed due to an Error"}

#check for Internet Explorer
try{
Write-Host -BackgroundColor black "Checking for Internet Explorer 11" 
"Checking for Internet Explorer 11" > $env:userprofile\Desktop\Go-Live\IE.txt
$IE = Get-RegKeyVal -RegKey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\svcVersion"
if ($IE -match "11.")
{Write-Host -ForegroundColor Green "`tInternet Explorer 11 is installed (Passed)"
"`tInternet Explorer $IE is installed (Passed)" >> $env:userprofile\Desktop\Go-Live\IE.txt}
else{Write-Host -ForegroundColor Green "`tInternet Explorer $IE is installed (Failed)"
"`tInternet Explorer $IE is installed (Failed)" >> $env:userprofile\Desktop\Go-Live\IE.txt}
}
catch
{ Write-Host -ForegroundColor Red "IE Check Failed due to an Error" }

#Get RDP Settings
try{
Write-Host -BackgroundColor black "Check RDP Settings:"
$MaxIdle = Get-RegKeyVal -RegKey "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime"
$MaxDisconnect = Get-RegKeyVal -RegKey "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime"
$fResetBroken = Get-RegKeyVal -RegKey "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fResetBroken"
"Checking For RDP Settings" > $env:userprofile\Desktop\Go-Live\RDP.txt

if ($fResetBroken -eq 1)
{    Write-Host -ForegroundColor Green "`tWhen a session limit is reached or connection is broken: Disconnect from Session (Passed)"
    "`tWhen a session limit is reached or connection is broken: Disconnect from Session (Passed)" >> $env:userprofile\Desktop\Go-Live\RDP.txt}
else{
Write-Host -ForegroundColor Red "`tWhen a session limit is reached or connection is broken: Disconnect from Session (falied)"
    "`tWhen a session limit is reached or connection is broken: Disconnect from Session (Failed)" >> $env:userprofile\Desktop\Go-Live\RDP.txt}
if ($MaxDisconnect -eq 300000)
{Write-Host -ForegroundColor Green "`tDisconnect from Session after 5min (Passed)"
 "`tDisconnect from Session after 5min (Passed)"  >> $env:userprofile\Desktop\Go-Live\RDP.txt}
else{
Write-Host -ForegroundColor Red "`tDisconnect from Session after 5min (Failed)"
 "`tDisconnect from Session after 5min (Failed)" >> $env:userprofile\Desktop\Go-Live\RDP.txt}
if ($MaxIdle -eq 300000)
{Write-Host -ForegroundColor Green "`tIdle Session Limite: 5 mins (Passed)"
"`tIdle Session Limit: 5 mins (Passed)" >> $env:userprofile\Desktop\Go-Live\RDP.txt}
else{
Write-Host -ForegroundColor Red "`tIdle Session Limite: 5 mins (Failed)"
"`tIdle Session Limit: 5 mins (Failed)" >> $env:userprofile\Desktop\Go-Live\RDP.txt}

$AllowGetHelp = Get-RegKeyVal -RegKey "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp"
if ($AllowGetHelp -eq 0)
{Write-Host -ForegroundColor Green "`tRemote Assistance: Get Help Disabled (Passed)"
"`tRemote Assistance: Get Help Disabled (Passed)"  >> $env:userprofile\Desktop\Go-Live\RDP.txt}
else{
Write-Host -ForegroundColor Red "`tRemote Assistance: Get Help Needs set (Failed)"
 "`tRemote Assistance: Get Help Needs set (Failed)" >> $env:userprofile\Desktop\Go-Live\RDP.txt}
 }
catch
{ Write-Host -ForegroundColor Red "RDP Check Failed due to an Error" }

#get users in the Remote Users Group
Try{
$strComputer = “.”
$computer = [ADSI](“WinNT://” + $strComputer + “,computer”)
$Group = $computer.psbase.children.find(“Remote Desktop Users”)
$members= $Group.psbase.invoke(“Members”) | %{$_.GetType().InvokeMember(“Name”, ‘GetProperty’, $null, $_, $null)}
"`r`nReview of Remote Desktop Users Group Required:" >> $env:userprofile\Desktop\Go-Live\RDP.txt
Write-Host  -ForegroundColor Yellow "`tReview of Remote Desktop Users Group Required"
ForEach($user in $members)
{Write-Host -ForegroundColor yellow "`t$user"
 "`t$user" >> $env:userprofile\Desktop\Go-Live\RDP.txt}
"`r`nTotal Remote Users: $($members.count)" >> $env:userprofile\Desktop\Go-Live\RDP.txt
}
catch
{Write-Host -ForegroundColor Red "Error Getting Users"
 "Error Getting Users" >> $env:userprofile\Desktop\Go-Live\RDP.txt}

Try
{
#Local Users
Write-Host -BackgroundColor black "Local Users"
Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$env:COMPUTERNAME'" | ft > "$env:userprofile\Desktop\Go-Live\netUsers.txt"
Write-Host -ForegroundColor Yellow "`tReview of Users Required"

#Local Users Group
Write-Host -BackgroundColor black "Local User Groups"
Get-WmiObject -Class Win32_Group -Filter "Domain='$env:COMPUTERNAME'" | ft > "$env:userprofile\Desktop\Go-Live\netlocalgroups.txt"
Write-Host -ForegroundColor Yellow "`tReview of Local Groups Required"

#Shares
Write-Host -BackgroundColor black "Shared folders"
Get-WmiObject -Class Win32_Share >  "$env:userprofile\Desktop\Go-Live\netshare.txt"
Write-Host -ForegroundColor Yellow "`tReview of Shares Required"

#group Policy
Write-Host -BackgroundColor black "Group Policy Check look at the auditing"
gpresult /Scope Computer /f /h  "$env:userprofile\Desktop\Go-Live\gpo-$env:COMPUTERNAME.html"
Write-Host -ForegroundColor Yellow "`tReview of the Group Policy Required"

#scheduled Tasks
"Scheduled Tasks:" > "$env:userprofile\Desktop\Go-Live\scheduledtasks.txt"
Write-Host -BackgroundColor black "Scheduled Tasks"
schtasks.exe >> "$env:userprofile\Desktop\Go-Live\scheduledtasks.txt"
Write-Host -ForegroundColor Yellow "`tReview of the Scheduled Tasks Required"

#Listening Ports and services
Write-Host -BackgroundColor black "Listening Ports and services..."
netstat -abo >  "$env:userprofile\Desktop\Go-Live\PortsServices.txt"
Write-Host -ForegroundColor Yellow "`tReview of Open Ports Required"
}
catch
{ Write-Host -ForegroundColor Red "MISC Ennumeration Check Failed due to an Error" }

#output HTML setting
#TODO: Find a better way to output the format
"<html>
<head>
</head>
<p>Script Version: $Version</p>

<br />
<a href='./OS.html' target='sub_mainFrame'>Operating System</a> 
<p> 
<a href='./time.txt' target='sub_mainFrame'>Time</a>
<p>
<a href='./SCCM.txt' target='sub_mainFrame'>SCCM</a>
<p>
<a href='./netAccounts.txt' target='sub_mainFrame'>Net Accounts</a>  
<p>
<a href='./LoginBanner.txt' target='sub_mainFrame'>Login Banner</a> 
<p>
<a href='./symantec.txt' target='sub_mainFrame'>Symantec</a>
<p>
<a href='./mcafee.txt' target='sub_mainFrame'>McAfee</a>
<p>
<a href='./SCOM.txt' target='sub_mainFrame'>SCOM</a>
<p>
<a href='./mrt.txt' target='sub_mainFrame'>MRT</a>
<p>
<a href='./IE.txt' target='sub_mainFrame'>IE</a>
<p>
<a href='./software.txt' target='sub_mainFrame'>Software Listing</a>
<p>
<a href='./RDP.txt' target='sub_mainFrame'>RDP</a>
<p>
<a href='./Logs.txt' target='sub_mainFrame'>Logs</a>  
<p>
<a href='./secpol.txt' target='sub_mainFrame'>Security Policy (Auditing)</a> 
<p>
<a href='./netUsers.txt' target='sub_mainFrame'>Net Users</a>  
<p> 
<a href='./netlocalgroups.txt' target='sub_mainFrame'>Local Groups</a>  
<p>  
<a href='./Scheduledtasks.txt' target='sub_mainFrame'>Scheduled Tasks</a>
<p>
<a href='./portsservices.txt' target='sub_mainFrame'>Ports</a>
<p>
<a href='./netshare.txt' target='sub_mainFrame'>Net Share</a>
<p>

<a href='./gpo-$env:COMPUTERNAME.html' target='sub_mainFrame'>Group Policy</a> 
<p> 
<br /></html>" | Out-File "$env:userprofile\Desktop\Go-Live\menu.htm"

"<html> 
<head> 
<title>Go Live report</title> 
</head> 
<frameset rows='100' framespacing='0' frameborder='0' border='0'> 
<frameset cols='15,85'> 
<frame src='menu.htm' name='leftFrame'> 
<frame src='sub_main.htm' name='sub_mainFrame'> 
</frameset> 
<noframes> 
<body> 
</body> 
</noframes> 
</frameset> 
</html> " | Out-File "$env:userprofile\Desktop\Go-Live\index.htm"

"<frameset rows='*' framespacing='1' border='1'> 
</frameset> " | Out-File "$env:userprofile\Desktop\Go-Live\sub_main.htm"


Write-Host "//////////////////////////////////////////////////////////////////////////////////////////////////////////"
$yesNo = Read-Host "Do you want to zip and send to a Security/IT Team Member? (Enter y to send or any other key to exit)"

if ($yesNo.ToUpper() -eq "Y")
{
function ZipFiles(){
 [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    [string[]]$EmailTo, $EmailFrom
  )
  #delete the zip if there is one already!
  if (Test-path "$env:userprofile\Desktop\$env:COMPUTERNAME.zip") {Remove-Item -Force "$env:userprofile\Desktop\$env:COMPUTERNAME.zip" }
  #$EmailTo
  #$EmailFrom
  Add-Type -Assembly System.IO.Compression.FileSystem
   $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
   [System.IO.Compression.ZipFile]::CreateFromDirectory("$env:userprofile\Desktop\Go-Live\", "$env:userprofile\Desktop\$env:COMPUTERNAME.zip", $compressionLevel, $false)

   Send-MailMessage -To $EmailTo -From $EmailFrom -Attachments "$env:userprofile\Desktop\$env:COMPUTERNAME.zip" -Subject "Go-Live for $env:COMPUTERNAME" -Body "Go Live Data" -SmtpServer $SMTPServer
   }

$et = Read-Host "Please enter an Email to send the report to"
$ef = Read-Host "Please enter your Email"
ZipFiles -EmailTo $et -EmailFrom $ef
}