rule gruntstager {
  meta:
    description = "Detect GruntStager loader, https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Grunt/GruntStager.cs"
    author = "Paul Melson @pmelson"
    date = "July 31, 2019"
  strings:
    $default00 = "Microsoft-IIS/7.5" wide
    $default01 = "gruntsvc" wide
    $class00 = "ExecuteStager"
    $class01 = "GruntStager"
    $class02 = "CookieWebClient"
    $var00 = "get_CookieContainer"
    $var01 = "set_CookieContainer"
    $var02 = "group0" wide
    $var03 = "group1" wide
    $var04 = "group2" wide
    $var05 = "group3" wide
    $var06 = "group4" wide
    $var07 = "group5" wide
  condition:
    uint16(0) == 0x5a4d and (all of ($default*) or all of ($class*) or all of ($var*))
}
