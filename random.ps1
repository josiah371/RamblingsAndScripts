$alpha = "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"
$num = "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0"
$special = ("!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "=", "-", "``", "\", "|", "]", "}", "[", "{", "'", "`"", ";", ":", "/", "?", ".", ">", ", ", "<")

#26 characters

#use first 3 nubers to generate a password
#number 1 is how many alphas, number 2 is how many num, number 3 is how many specials


$a = [System.Random]::new()

$ran = $a.Next()/100000000
#random grab letter
$alpha[[int]$ran]

#do until within range
$b = [System.Random]::new()
$ran = $b.Next()/100000000
$num[[int]$ran]

#do until within range
$c = [System.Random]::new()
$ran = $c.Next()/100000000
$special[[int]$ran]