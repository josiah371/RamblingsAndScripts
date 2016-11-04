<#
.SYNOPSIS
Migrates registry settings from EMET 5.5 beta 1 and earlier to the new registry format.

Note that it is recommended that you export HKLM\Software\Microsoft\EMET to a backup
before committing any changes to EMET settings.

.DESCRIPTION
EMET 5.5 beta 1 and earlier used a different registry format to store settings from
the format used beginning in EMET 5.5 beta 2. This script migrates settings found in
the local registry from the old format to the new. It can output the new settings in
the form of a "Registration Entries" (*.reg) file, or modify the local registry
directly. It can also delete the old settings after migration has completed. Finally,
it can report any missing root certificates referenced in pinning rules.

Modification of the local registry requires administrative rights.

Note that this script does not modify Group Policy settings, only "regular" settings
found under HKLM\Software\Microsoft\EMET.

For more information, run Get-Help Migrate-EmetSettings.ps1 -Detailed.

.PARAMETER RegFile
Specify a file path to output the new settings in the form of a "Registration Entries"
(*.reg) file. The resulting file can be imported into the current computer or other
computers; for example, using the "reg.exe import" command. This option does not
require administrative rights, assuming that the target file location is writable.
The script fails if this option is specified and the target file cannot be written.

.PARAMETER MissingCertCsv
Specify a file path to output information about root certificates specified in pinning
rules that cannot be found in the current user's Trusted Root Certification Authorities
certificate store. The previous EMET format referenced the certificate's Issuer Name
and Serial Number; the new format references its thumbprint (sometimes also called a
"fingerprint"). The thumbprint cannot be found if the certificate is not in the current
user's store. Information about any such certificates are written into a tab-delimited
CSV file, with columns indicating the referencing pinning rule, the issuer/subject name,
and the serial number. These can be resolved by using a different computer or by
installing the necessary root certificates on the computer. (This option does not
require administrative rights, assuming the file is in a writable location. The script
fails if this option is specified and the target file cannot be written.)

.PARAMETER UpdateLocalRegistry
If this option is specified, the new settings are written to the registry of the local
computer. This option requires administrative rights.

.PARAMETER DeleteAfterMigrate
If this option is specified, old settings are removed from the local registry after the
RegFile or UpdateLocalRegistry migration steps (or both, if selected) have been
completed. Be careful about this option, as there is no "undo" feature. It is recommended
that you export HKLM\Software\Microsoft\EMET to a backup before using this option.

.EXAMPLE

.\Migrate-EmetSettings.ps1 -RegFile .\NewEmetSettings.reg -MissingCertCsv .\MissingCerts.csv

Reads exising settings, writes the new corresponding settings to the NewEmetSettings.reg
file. Any missing certificates specified in pinning rules are written to MissingCerts.csv.
This example does not require administrative rights.

.EXAMPLE

.\Migrate-EmetSettings.ps1 -UpdateLocalRegistry -DeleteAfterMigrate

Reads existing settings, writes the new corresponding settings into the local registry,
and deletes the old settings. This example requires administrative rights.
#>

param(
	[parameter(Mandatory=$false)]
	[String]
	$RegFile,

	[parameter(Mandatory=$false)]
	[String]
	$MissingCertCsv,

	[switch]
	$UpdateLocalRegistry = $false,

	[switch]
	$DeleteAfterMigrate = $false
)

if (!$RegFile -and !$UpdateLocalRegistry)
{
	Write-Error "Nothing to do: neither -RegFile nor -UpdateLocalRegistry selected."
	exit
}

$mainkey           = "HKLM:\SOFTWARE\Microsoft\EMET\"
$oldSettingKey     = "HKLM:\SOFTWARE\Microsoft\EMET\_settings_\"
$oldPinnedSitesKey = "HKLM:\SOFTWARE\Microsoft\EMET\_settings_\Pinning\PinnedSites\"
$oldPinRulesKey    = "HKLM:\SOFTWARE\Microsoft\EMET\_settings_\Pinning\PinRules\"
$newSettingKey     = "HKLM:\SOFTWARE\Microsoft\EMET\AppSettings"
$newPinRootKey     = "HKLM:\SOFTWARE\Microsoft\EMET\CertPinning"
$newPinnedSitesKey = "HKLM:\SOFTWARE\Microsoft\EMET\CertPinning\Sites"
$newPinRulesKey    = "HKLM:\SOFTWARE\Microsoft\EMET\CertPinning\Rules"

if ($RegFile)
{
	"Windows Registry Editor Version 5.00" | Out-File -FilePath $RegFile -Encoding ASCII -ErrorVariable RegFileError
	if ($RegFileError)
	{
		exit
	}
	""                                                         | Out-File -FilePath $RegFile -Encoding ASCII -Append
	"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EMET\AppSettings]" | Out-File -FilePath $RegFile -Encoding ASCII -Append
}
if ($MissingCertCsv)
{
	"MISSING ROOT CERT`tSerial number`tPinning rule" | Out-File -FilePath $MissingCertCsv -Encoding ASCII -ErrorVariable CertCsvFileError
	if ($CertCsvFileError)
	{
		exit
	}
}
if ($UpdateLocalRegistry)
{
	mkdir $newSettingKey -ErrorVariable makeKeyError > $null 2>&1
	if ($makeKeyError)
	{
		# OK if the key already exists. Assume that an IOException is key-already-exists.
		# Anything else, get out.
		if ($makeKeyError.Count -gt 0 -and $makeKeyError[0].Exception.GetType().Name -ne "IOException")
		{
			$makeKeyError
			exit
		}
	}
	mkdir $newPinRootKey > $null
	mkdir $newPinnedSitesKey > $null
	mkdir $newPinRulesKey > $null
}

$settingList = (dir $oldSettingKey | ?{ $_.PsChildName -ne "Pinning"})
$settingTable = @{}

$settingList | %{
	$guid = $_.PsChildName
	$settings = gp ($oldSettingKey + $guid)
	$settingTable.Add($guid, $settings)
}

$appList = (dir $mainkey | ?{ $_.PsChildName -ne "_settings_" -and $_.PsChildName -ne "AppSettings" -and $_.PsChildName -ne "CertPinning" })
$appTable = @{}

$appList | %{
	$appsubkey = $_
	$valnames = $appsubkey.GetValueNames()
	$valnames | %{
		$appguid = $appsubkey.GetValue($_)
		$settings = $settingTable[$appguid]
		$appTable.Add($_, $settings)
	}
}

$appTable.Keys | %{
	$pathspec = $_
	$settings = $appTable[$pathspec]
	$newSpec = ""

	# Default-on mitigations
	if ($settings.BottomUpASLR -eq 0)
		{ $newSpec += " -BottomUpASLR" }
	if ($settings.Caller -eq 0)
		{ $newSpec += " -Caller" }
	if ($settings.DEP -eq 0)
		{ $newSpec += " -DEP" }
	if ($settings.EAF -eq 0)
		{ $newSpec += " -EAF" }
	if ($settings.HeapSpray -eq 0)
		{ $newSpec += " -HeapSpray" }
	if ($settings.LoadLib -eq 0)
		{ $newSpec += " -LoadLib" }
	if ($settings.MandatoryASLR -eq 0)
		{ $newSpec += " -MandatoryASLR" }
	if ($settings.MemProt -eq 0)
		{ $newSpec += " -MemProt" }
	if ($settings.NullPage -eq 0)
		{ $newSpec += " -NullPage" }
	if ($settings.SEHOP -eq 0)
		{ $newSpec += " -SEHOP" }
	if ($settings.SimExecFlow -eq 0)
		{ $newSpec += " -SimExecFlow" }
	if ($settings.StackPivot -eq 0)
		{ $newSpec += " -StackPivot" }

	# Default-off mitigations
	if ($settings.ASR -eq 1)
		{ $newSpec += " +ASR" }
	if ($settings."EAF+" -eq 1)
		{ $newSpec += " +EAF+" }

	$heapPagesDefault = "0x0a040a04;0x0a0a0a0a;0x0b0b0b0b;0x0c0c0c0c;0x0d0d0d0d;0x0e0e0e0e;0x04040404;0x05050505;0x06060606;0x07070707;0x08080808;0x09090909;0x20202020;0x14141414"
	if ($settings.heap_pages -ne $nul -and $settings.heap_pages -ne $heapPagesDefault)
		{ $newSpec += " heap_pages:" + $settings.heap_pages }
	if ($settings.eaf_modules -ne $nul -and $settings.eaf_modules.length -gt 0)
		{ $newSpec += " eaf_modules:" + $settings.eaf_modules }
	if ($settings.asr_modules -ne $nul -and $settings.asr_modules.length -gt 0)
		{ $newSpec += " asr_modules:" + $settings.asr_modules }
	if ($settings.asr_zones -ne $nul -and $settings.asr_zones.length -gt 0)
		{ $newSpec += " asr_zones:" + $settings.asr_zones }
	if ($settings.sim_count -ne $nul -and $settings.sim_count.length -gt 0)
		{ $newSpec += " sim_count:" + $settings.sim_count }

	if ($RegFile)
	{
		("`"" + $pathspec + "`"=`"" + $newSpec.Trim() + "`"").Replace("\", "\\") | Out-File -FilePath $RegFile -Encoding ASCII -Append
	}
	if ($UpdateLocalRegistry)
	{
		Set-ItemProperty -Path $newSettingKey -Name $pathspec -Value $newSpec.Trim()
	}
}

$pinRulesList = (dir $oldPinRulesKey)
$ruleTable = @{}

$pinRulesList | %{
	$guid = $_.PsChildName
	$ruleDetails = gp ($oldPinRulesKey + $guid)
	$ruleTable.Add($guid, $ruleDetails)
}

# Create a new lookup, rather than go to the trouble of adding this to ruleTable.
$thumbTable = @{}
$missingCerts = @()
$ruleTable.Keys | %{
	$guid = $_
	$details = $ruleTable[$_]
	$rootCertArray = $details.RootCerts
	$sRootCerts = ""
	for ( $ix = 0; $ix -lt $rootCertArray.Length - 2; $ix += 3)
	{
		$issuerName = $rootCertArray[$ix]
		$serialNum = $rootCertArray[$ix + 1]
		$certs = (dir Cert:\CurrentUser\Root | ?{ $_.Issuer -eq $issuerName -and $_.SerialNumber -eq $serialNum })
		if ($certs -eq $null)
		{
			$missingCerts += ($issuerName + "`t" + $serialNum + "`t" + $details.Name)
		}
		else
		{
			$certs | %{ $sRootCerts += $_.Thumbprint + "; " }
		}
	}
	$thumbTable.Add($guid, $sRootCerts)
}

if ($missingCerts)
{
	"Root certs identified in rules not found."
	if ($MissingCertCsv)
	{
		$missingCerts | Out-File -FilePath $MissingCertCsv -Encoding ASCII -Append
	}
}

if ($RegFile)
{
	""                                                               | Out-File -FilePath $RegFile -Encoding ASCII -Append
	"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EMET\CertPinning\Rules]" | Out-File -FilePath $RegFile -Encoding ASCII -Append
}

$ruleTable.Keys | %{
	$details = $ruleTable[$_]
	$thumbprints = $thumbTable[$_]
	$ruleName = $details.Name
	$ruleSettings = ""
	if ($details.BlockingRule -ne $null -and $details.BlockingRule -ne 0)
	{
		$ruleSettings += "BLOCK; "
	}
	else
	{
		$ruleSettings += "WARN; "
	}
	$ruleSettings += $thumbprints
	if ($details.Expiration)
	{
		$dt = [DateTime]0
		if ([DateTime]::TryParse($details.Expiration, [ref] $dt))
		{
			$ruleSettings += ("expiration:" + $dt.Year.ToString("0000") + "-" + $dt.Month.ToString("00") + "-" + $dt.Day.ToString("00") + "; ")
		}
	}

	if ($RegFile)
	{
		("`"" + $ruleName + "`"=`"" + $ruleSettings.Trim() + "`"").Replace("\", "\\") | Out-File -FilePath $RegFile -Encoding ASCII -Append
	}
	if ($UpdateLocalRegistry)
	{
		Set-ItemProperty -Path $newPinRulesKey -Name $ruleName -Value $ruleSettings.Trim()
	}
}

if ($RegFile)
{
	""                                                               | Out-File -FilePath $RegFile -Encoding ASCII -Append
	"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EMET\CertPinning\Sites]" | Out-File -FilePath $RegFile -Encoding ASCII -Append
}

$pinnedSitesList = (dir $oldPinnedSitesKey)
$siteTable = @{}

$pinnedSitesList | %{
	$siteInfo = gp ($oldPinnedSitesKey + $_.PsChildName)
	$domainName = $siteInfo.DomainName
	$bActive = ($siteInfo.Active -ne 0)
	$guid = $siteInfo.PinRuleID
	$ruleDetails = $ruleTable[$guid]
	if ($ruleDetails)
	{
		$ruleName = $ruleDetails.Name
		if ($bActive) { $ruleSettings = "+" } else { $ruleSettings = "-" }
		$ruleSettings += $ruleName
		if ($RegFile)
		{
			"`"" + $domainName + "`"=`"" + $ruleSettings.Trim() + "`"" | Out-File -FilePath $RegFile -Encoding ASCII -Append
		}
		if ($UpdateLocalRegistry)
		{
			Set-ItemProperty -Path $newPinnedSitesKey -Name $domainName -Value $ruleSettings.Trim()
		}
	}
	else
	{
		"Pinned site is missing its rule: " + $domainName
	}
}

if ($DeleteAfterMigrate)
{
	pushd $mainkey
	Get-ChildItem | ?{ $_.PsChildName -ne "AppSettings" -and $_.PsChildName -ne "CertPinning" } | %{ Remove-Item $_.PsChildName -Force -Recurse }
	popd
}

# SIG # Begin signature block
# MIIkFwYJKoZIhvcNAQcCoIIkCDCCJAQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBO3tAD2Acaq6Ve
# Uvifm091pjxloHcUu00dZpTG2jWabaCCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
# lIbbQRk4AAAAAABkMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTUxMDI4MjAzMTQ2WhcNMTcwMTI4MjAzMTQ2WjCBgzEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9Q
# UjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAky7a2OY+mNkbD2RfTahYTRQ793qE/DwRMTrvicJK
# LUGlSF3dEp7vq2YoNNV9KlV7TE2K8sDxstNSFYu2swi4i1AL3X/7agmg3GcExPHf
# vHUYIEC+eCyZVt3u9S7dPkL5Wh8wrgEUirCCtVGg4m1l/vcYCo0wbU06p8XzNi3u
# XyygkgCxHEziy/f/JCV/14/A3ZduzrIXtsccRKckyn6B5uYxuRbZXT7RaO6+zUjQ
# hiyu3A4hwcCKw+4bk1kT9sY7gHIYiFP7q78wPqB3vVKIv3rY6LCTraEbjNR+phBQ
# EL7hyBxk+ocu+8RHZhbAhHs2r1+6hURsAg8t4LAOG6I+JQIDAQABo4IBfzCCAXsw
# HwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBgjdMCAEwHQYDVR0OBBYEFFhWcQTw
# vbsz9YNozOeARvdXr9IiMFEGA1UdEQRKMEikRjBEMQ0wCwYDVQQLEwRNT1BSMTMw
# MQYDVQQFEyozMTY0Mis0OWU4YzNmMy0yMzU5LTQ3ZjYtYTNiZS02YzhjNDc1MWM0
# YjYwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29k
# U2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYB
# BQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4ICAQCI4gxkQx3dXK6MO4UktZ1A1r1mrFtXNdn06DrARZkQTdu0
# kOTLdlGBCfCzk0309RLkvUgnFKpvLddrg9TGp3n80yUbRsp2AogyrlBU+gP5ggHF
# i7NjGEpj5bH+FDsMw9PygLg8JelgsvBVudw1SgUt625nY7w1vrwk+cDd58TvAyJQ
# FAW1zJ+0ySgB9lu2vwg0NKetOyL7dxe3KoRLaztUcqXoYW5CkI+Mv3m8HOeqlhyf
# FTYxPB5YXyQJPKQJYh8zC9b90JXLT7raM7mQ94ygDuFmlaiZ+QSUR3XVupdEngrm
# ZgUB5jX13M+Pl2Vv7PPFU3xlo3Uhj1wtupNC81epoxGhJ0tRuLdEajD/dCZ0xIni
# esRXCKSC4HCL3BMnSwVXtIoj/QFymFYwD5+sAZuvRSgkKyD1rDA7MPcEI2i/Bh5O
# MAo9App4sR0Gp049oSkXNhvRi/au7QG6NJBTSBbNBGJG8Qp+5QThKoQUk8mj0ugr
# 4yWRsA9JTbmqVw7u9suB5OKYBMUN4hL/yI+aFVsE/KJInvnxSzXJ1YHka45ADYMK
# AMl+fLdIqm3nx6rIN0RkoDAbvTAAXGehUCsIod049A1T3IJyUJXt3OsTd3WabhIB
# XICYfxMg10naaWcyUePgW3+VwP0XLKu4O1+8ZeGyaDSi33GnzmmyYacX3BTqMDCC
# B3owggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkw
# OVoXDTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAx
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBN
# NLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJ
# DXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv
# 56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN
# 1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+
# sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzlu
# ZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKu
# HCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8
# rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43s
# TUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/
# dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCI
# F96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUH
# MAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3
# LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw+
# +MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS
# 0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELuk
# qQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q
# 3fMOr5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgy
# cScaf7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8V
# fUWnduVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbR
# BrF1HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/Q
# ACnFsZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL
# /9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9B
# CrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghXb
# MIIV1wIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAA
# ZEeElIbbQRk4AAAAAABkMA0GCWCGSAFlAwQCAQUAoIHKMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCBKoHBYcY3XMXF4MQ1PWrrrlRfp5DcJmnuIQ2ih1suMpzBeBgor
# BgEEAYI3AgEMMVAwTqA2gDQARQBNAEUAVAAgADUALgA1ACAAUwBlAHQAdABpAG4A
# ZwAgAGMAbwBuAHYAZQByAHQAZQByoRSAEmh0dHA6Ly9ha2EubXMvZW1ldDANBgkq
# hkiG9w0BAQEFAASCAQCADuxlYqQAoPBGVXKZtJQu9hm5xeVvBoKGw9ys1aHCZW9p
# BHkMNnOBWDNW4+l3L489u0GoIvtqGHLaAgYACsSNBTy26zlrB6lflv8ZLhui741N
# 8wuWAp33OD6C7xGD4ofjn59I1VdhO1r2qXxrPlkNH3lkvFNPhzciEvNJkWHNEcrN
# LVjt8BkJZH5U9o3WtRotkLTTp/YzSauisqoyw3T1aQRoZEJ0WerP0jv0fPeL68pg
# YNyd3HIYF3Dyv9QooFHj1o4K1K9/R9CFjuYnHDe2/18DZz0nZr1mmuo6C+p1sG6H
# yfkxdZ3RtI3bm91cmn8E/WXqRxgSjgj4uoxqI1VQoYITSTCCE0UGCisGAQQBgjcD
# AwExghM1MIITMQYJKoZIhvcNAQcCoIITIjCCEx4CAQMxDzANBglghkgBZQMEAgEF
# ADCCAT0GCyqGSIb3DQEJEAEEoIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEw
# DQYJYIZIAWUDBAIBBQAEIGIpEESqD69YkxEOdfqmPEJeSB02Bk+l+jXKJyzdSAAW
# AgZWq3STGxcYEzIwMTYwMjAyMDYzMjEzLjUzOFowBwIBAYACAfSggbmkgbYwgbMx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1P
# UFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjo3QUZBLUU0MUMtRTE0MjElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDswwggZxMIIEWaAD
# AgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3
# MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWl
# CgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/Fg
# iIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeR
# X4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/Xcf
# PfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogI
# Neh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB
# 5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvF
# M2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8E
# gZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcC
# AjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUA
# bgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Pr
# psz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOM
# zPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCv
# OA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v
# /rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99
# lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1kl
# D3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQ
# Hm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30
# uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp
# 25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HS
# xVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi6
# 2jbb01+P3nSISRIwggTaMIIDwqADAgECAhMzAAAAa8d53aMvuF5ZAAAAAABrMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE1
# MTAwNzE4MTcyOVoXDTE3MDEwNzE4MTcyOVowgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjo3QUZBLUU0MUMtRTE0MjElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AKn1VyccsVeOOGj1wqgN7oxGzT/X7Qv+jUYtnIcfaPET8lGyssmrEDprpMBs1am9
# QhBtErn8PrvoHrJfR1aMUhR2J+0vgMBLsnCSHMnS4ELgSF61urCod/x+iXrfFm/1
# /VXrNRSI2YrUMYtDFCGubn5ibumSVB7WxLurCUCHB49PHyLZbMcc3GUoCSJdgTiW
# /YX013L7u12UxdAERBOQ7aqZR6BFhoeGI9SgKMzgmBiVCZ4ZhRFJr914A4923J0M
# 4el/8ZiOSADQYowP5UaZJfmSuROM/vH4G6VnoHEFkIS3Kpqv+USp77MxVHp0+ZX5
# uviMFFTyl/uRYAcgsJJokysCAwEAAaOCARswggEXMB0GA1UdDgQWBBRkVvHAfN1m
# m5tRaC/+bYhjwycFkzAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQCBK/cE5pMu
# wQBfN4Jz3AdCtJDvs1PLbD23eXaJn4tTvNCTGnNqDf83lX6aA1RtZxeNHEHI2z5m
# qXppKY2TUmXe/8YdligBjJkXTmwYfp3dKdiGmErdDre3qsmiYCD/RuZb7kHLn7HJ
# 9pxgAXdGUghNkhChp/Rfe/Sg2vCMxJV789TSBQEEwBMdDpBJqPoceeMSOa/s0M7a
# ReV5ZFO6tY1Cblm118rWQ6HO8XqzQ0VmRQ2fk7x8y4QuJJxsrbSfOgJgjrjAgOZx
# 2Q93dmnSMMI6RS1COcxohXv2nEChdcV23AwW7sM7YWeTzw3+lhJ6PH2ba3823TCs
# Sz3fiMs+tFqtoYIDdTCCAl0CAQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5D
# aXBoZXIgRFNFIEVTTjo3QUZBLUU0MUMtRTE0MjElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQCASkKYsYU6naFF
# O7bDnjwZb5gp86CBwjCBv6SBvDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMg
# RVNOOjRERTktMEM1RS0zRTA5MSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3Vy
# Y2UgTWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA2lq1lzAiGA8yMDE2MDIw
# MjA0NTY1NVoYDzIwMTYwMjAzMDQ1NjU1WjBzMDkGCisGAQQBhFkKBAExKzApMAoC
# BQDaWrWXAgEAMAYCAQACAUQwBwIBAAICGOkwCgIFANpcBxcCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAaAKMAgCAQACAxbjYKEKMAgCAQACAwehIDAN
# BgkqhkiG9w0BAQUFAAOCAQEAxAwGfMkvQbBGtpSs8T99et5mJlNMl+vWWYh6jMPm
# zDu0Bi+9ljqdcFnuL0TvrlxNxg0N39yVs9ojfFApdVQZbLzpNpKISdX1DB1H1+A1
# fBTtrLrWJp6MJ7EleUsrmqiAjJKm4IJ/7sT7wYibVJUOytN+QSDpCC1L8wc27f+N
# Fyu50xy7eIehambTw/rjTjSXdEdhfJXWgyMrReYkwJ4Aq4Yr+4dAVWDJSInPUQY/
# INB9MvWr7WrlEIoTP9CQTa4L0ypSloDQPTWIh7hZwkHAaLurnQhFOleEPyTmZwl6
# jdA2/e4X+7tbI+Dq5SGANJ0Iup27ZTBDfNqncZfNur0GfTGCAvUwggLxAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAAa8d53aMvuF5ZAAAA
# AABrMA0GCWCGSAFlAwQCAQUAoIIBMjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIOSHXFN4NMu3GGzuCC4NnVtrT4DSFJHTJHqEFZn0
# FPNQMIHiBgsqhkiG9w0BCRACDDGB0jCBzzCBzDCBsQQUgEpCmLGFOp2hRTu2w548
# GW+YKfMwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AGvHed2jL7heWQAAAAAAazAWBBQUUoPxCtpvLWarl4bdBfifYgz19TANBgkqhkiG
# 9w0BAQsFAASCAQBmejAA39OQ6tJvs4oa51UhNZQlpPHALIQK/wzXmeyqN1gaKeKD
# LuyTteTJwFf6ZtWNVnBEsJfarq+lnZ7qFJ2SROePj3bgsPKUcfecoytLxPT0vlZT
# Hz1cOwIhhfQ96Jo2HjRv8a86TZrarxGamxmTbsvFKt5UNRZJ2tHvhgbs0PL/apPw
# J087CXzjXtiuqMlbstGhPSeYxMM7i4eDx6040uNjPauz9aS/UrUFifBWZKT3Zidd
# AnxicLnrr90knWeuUbD1nAcJg9wwBHqBbTPy8xiOEpQwaMkQy1RTed+6ThoKSE5q
# kuh+2QS4qOWsG0Lwwxl84CqZ307e3zVXL7Pr
# SIG # End signature block
