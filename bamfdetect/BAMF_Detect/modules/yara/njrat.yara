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
        $a4 = "|'|'|" wide

        $b0 = "[TAB]" wide
        $b1 = "[TAP]" wide
        $b2 = " & exit" wide
        $b3 = "!'!@!'!" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
        $c4 = "/c ping 0 -n 2 & del " wide
        $c5 = "cmd.exe /C Y /N /D Y /T 1 & Del " wide
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

rule njrat07multi {
  meta:
    author = "Paul Melson @pmelson"
    description = "njRat 0.7 Multi-Host variant"
  strings:
    $ver = "0.7 MultiHost" wide
    $cfg1 = "[ENTER]" wide
    $cfg2 = "[TAP]" wide
    $cfg3 = "SEE_MASK_NOZONECHECKS" wide
    $drop1 = "schtasks /create /sc minute /mo 1 /tn" wide
    $drop2 = "del Del.bat" wide
    $drop3 = "Sleep 5" wide
  condition:
    uint16(0) == 0x5a4d and $ver and
                 ( 1 of ($cfg*) or
                   2 of ($drop*) )
}

rule njrat07nyancat {
  meta:
    author = "Paul Melson @pmelson"
    description = "njRat 0.7NC NYAN CAT variant"
  strings:
    $ver0 = "0.7NC" wide
    $ver1 = "TllBTiBDQVQ=" wide
    $ver2 = "0.7d" wide
    $cfg0 = "[ENTER]" wide
    $cfg1 = "[TAP]" wide
    $drop0 = "cmd.exe /C Y /N /D Y /T 1 & Del " wide
  condition:
    uint16(0) == 0x5a4d and
                 1 of ($ver*) and
                 ( 1 of ($cfg*) or
                   1 of ($drop*))
}
