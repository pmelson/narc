rule njrat07golden {
  strings:
    $mz = { 4d 5a }
    $s0 = "Hassan firewall add allowedprogram" wide
    $s1 = "Hassan firewall delete allowedprogram" wide
    $s2 = "schtasks /create /sc minute /mo 1 /tn Server /tr" wide
    $s3 = "cmd.exe /c ping 0 -n 2 & del" wide
    $njrat = "Njrat 0.7 Golden By Hassan Amiri"
  condition:
    $mz at 0 and (all of ($s*) or $njrat)
}
