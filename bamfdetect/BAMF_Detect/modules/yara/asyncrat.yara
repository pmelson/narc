rule asyncrat {
  meta:
    author = "Paul Melson @pmelson"
    descriptuon = "AsyncRAT (aka NYAN) .NET RAT"
    hashes = "b40486b43cf193b26509e85cfebd0891,c3c5114e9ba59f5031bec7251c530b26,003560f0ee0324f8892eb1fd4ba61d23"
  strings:
    $plain_async = "AysncRAT" wide
    $plain_extfmt = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
    $plain_sc2 = "\\root\\SecurityCenter2" wide
    $plain_av = "Select * from AntivirusProduct" wide
    $b64regex_00 = /[A-Za-z0-9\/\-\=]{88}/ wide
    $b64regex_01 = /[A-Za-z0-9\/\-\=]{108}/ wide
  condition:
    uint16(0) == 0x5a4d and 
    any of ($plain*) and 
    any of ($b64*)
}
