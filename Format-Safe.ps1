function format-safe()
{
Param(
[String]$initalString
)
  $modifiedString = $initalString.replace("http","hxxp")
  $modifiedString = $modifiedString.replace(".","[.]")
  $modifiedString = $modifiedString.replace("@","[@]")
  return $modifiedString
}
