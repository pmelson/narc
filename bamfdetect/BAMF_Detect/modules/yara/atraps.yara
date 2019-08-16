rule atraps {
  strings:
    $config00 = "\\root\\SecurityCenter2" wide
    $config01 = "Select * from AntivirusProduct" wide
    $config02 = "pongPing" wide
    $config10 = { 2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 31 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 22 }
  condition:
    uint16(0) == 0x5a4d
    and all of them
}
