Function Convert-HexToASCII()
{
Param(
[string]$hexString 
)

if ($hexString.Contains(" "))
    {
        $hexString.Split(" ") | foreach{[char]([convert]::ToInt16($_,16))} | foreach {$c = $c + $_}
    }
    else
    {
    if ($hexString.Length % 2 -eq 0)
    {
      $hexString = $hexString -replace '(..)','$1 ' #match any 2 char and replace with that string and a space.
       $hexString = $hexString.trim(" ")
        Write-Host $hexString
        $hexString.Split(" ") | foreach{[char]([convert]::ToInt16($_,16))} | foreach {$c = $c + $_}
    }
    else
    {
     Write-Host "Not a hex String"
    }
    }
}
