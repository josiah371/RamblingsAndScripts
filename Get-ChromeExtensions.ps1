# List of Extensions to check
$extensions = "aapocclcgogkmnckokdopfmhonfmgoek" , "aohghmighlieiainnegkcijnfilokake" , "apdfllckaahabafndbhieahigkjlhalf" , "blpcfgokakmgnkcojhhkbfbldkacnbeo" , "efaidnbmnnnibpcajpcglclefindmkaj" , "felcaaldnbdncclmgdcncolpebgiejap" , "ghbmnnjooekpmoecnnnilnnbdlolhkhi" , "jjkchpdmjjdmalgembblgafllbpcjlei" , "nmmhkkegccagdldgiimedpiccmgmieda" , "pjkljhegncpnkpknbcohdijeoejaedia" , "pkedcjkdefgpdelpbcmbmeomcjbeemfm"
#$extensions = get-content c:\somepath
Foreach ($e in $extensions){
$URI = 'https://chrome.google.com/webstore/detail/'
$app_ID = $e
# WebRequest to Chrome Web Store
$data = Invoke-WebRequest -Uri ($URI + $app_ID) | select Content
$data = $data.Content
# Regex which pulls the title from og:title meta property
$title = [regex] '(?<=og:title" content=")([\S\s]*?)(?=">)' 
write-output $title.Match($data).value.trim() 
}
