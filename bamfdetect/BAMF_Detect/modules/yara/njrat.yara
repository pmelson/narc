rule njrat{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-27"
        description = "Identify njRat"
    strings:
        $a0 = "netsh firewall delete allowedprogram " wide
        $a1 = "netsh firewall add allowedprogram " wide
        $a2 = "SEE_MASK_NOZONECHECKS" wide
        $a3 = "fizwrzwezwwalzwl dzwezwlzwezwte azwllowedprogrzwam " wide

        $b0 = "[TAB]" wide
        $b1 = "[TAP]" wide
        $b2 = " & exit" wide
        $b3 = "!'!@!'!" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
        $c4 = "/c ping 0 -n 2 & del " wide
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}

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

