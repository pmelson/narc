rule njratbr {
  meta:
    author = "Paul Melson @pmelson"
    description = "Brazilian language variant of njRat 0.7d"
  strings:
    $err0 = "Eroor" wide
    $err1 = "Windows to Erorr " wide
    $err2 = "Windows Erorr" wide
    $ver = "0.7d" wide
    $av = "Select * From AntiVirusProduct" wide
    $name0 = "Doni!" wide
    $name1 = "!~ Hacker ~!" wide
    $name2 = "FRANSESCO" nocase wide
  condition:
    uint16(0) == 0x5a4d and 1 of ($err*) and $ver and $av and 1 of ($name*)
}
