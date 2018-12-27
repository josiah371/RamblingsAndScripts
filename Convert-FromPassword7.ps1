# I cant remember who gave me this originally but works like a charm #
<# #####
.Synopsis
   Decrypts Cisco "PASSWORD 7" passwords.
.DESCRIPTION
   Takes Cisco Password 7 encrypted text from router and switch configs
   and decrypts it to get the password back in plain text.
.EXAMPLE
   PS C:\> Import-Module c:\downloads\Unprotect-CiscoPassword7.ps1
   PS C:\> Unprotect-CiscoPassword7 '025756085F'
   1234
.EXAMPLE
   PS C:\> Unprotect-CiscoPassword7 -Password7Text '025756085F'
   1234
.EXAMPLE
   PS C:\> '025756085F' | Unprotect-CiscoPassword7
   1234
.EXAMPLE
   # Take the lines from your cisco config which contain "Password 7"
   # and take the password from the end of them and decrypt them all.
   PS C:\> Get-ChildItem C:\CiscoConfigs\ -Recurse   | 
               Select-String -Pattern 'password 7'    |
               ForEach-Object { Unprotect-CiscoPassword7 $_.Line }
   1234
   letmein
   secretPasswordHere
   .. etc.
.INPUTS
    A string representing an encrypted password
.OUTPUTS
    A string containing the password in plain text form
#>

function Unprotect-CiscoPassword7 {

    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Encrypted password
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    Position=0)]
        [ValidateScript({
                # Check length, starting pattern, and split out entire config line (if necessary).
                if ($_ -match 'password 7')
                {
                    $_ = (-split $_)[-1]
                }

                ($_.Length % 2 -eq 0) -and ($_ -match '^[0-9][0-9]') -and (([int]$_.Substring(0, 2)) -le 15)
            })]
        [string]$Password7Text
    )


    Begin
    {   
        # Same decryption key for everyone
        $key = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
    }
    
    Process
    {
        # Handle if the input is just the password, or the full config line
        if ($Password7Text -match 'password 7')
        {
            $Password7Text = (-split $Password7Text)[-1]
        }

        # First two characters' value is the offset into the key where the decryption starts.
        $seed = [int]$Password7Text.substring(0, 2)

        # Take two characters at a time from the rest of the string
        # convert them from hex to decimal, and XOR with the next key position
        # (wrapping around the key if needed)
        # convert the resulting values to characters
        $plainTextBytes = [regex]::Matches($Password7Text.SubString(2), '..').Value | 
            ForEach-Object { 
    
                [char]([convert]::ToInt32($_, 16) -bxor $key[$seed++])
                $seed = $seed % $key.Length
        
            }

        -join $plainTextBytes    
    }

}
