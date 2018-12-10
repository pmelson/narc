rule remcos {
  strings:
    $cfg = "SETTINGS" wide
    $remcos0 = "Remcos_Mutex_Inj"
    $remcos1 = " * REMCOS v"
    $remcos2 = " * Breaking-Security.Net"
    $remcos3 = "Initializing connection to C&C..."
    $func0 = "initremscript"
    $func1 = "remscripterr"
    $func2 = "remscriptexecd"
    $func3 = "remscriptsuccess"
  condition:
    uint16(0) == 0x5a4d and $cfg and (any of ($remcos*) or all of ($func*))
}
