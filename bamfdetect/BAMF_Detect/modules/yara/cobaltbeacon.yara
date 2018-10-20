rule cobaltbeacon {
  meta:
    author = "Paul Melson @pmelson"
    description = "Cobalt Strike Beacon PE strings"
    sha256 = "fa7c71311369e5444d688ba65013e7693073a1ca5d7093a705c9401f57c1a14b"
  strings:
    $mz = "MZ"
    $beacon0 = "kerberos ticket purge failed:"
    $beacon1 = "kerberos ticket use failed:"
    $beacon2 = "%d is an x64 process (can't inject x86 content)"
    $beacon3 = "%d is an x86 process (can't inject x64 content)"
    $beaconcnc0 = "cdn.%x%x.%s"
    $beaconcnc1 = "www6.%x%x.%s"
    $beaconcnc2 = "www.%x%x.%s"
    $beaconcnc3 = "POST"
    $beaconcnc4 = "GET"
    $posh0 = "powershell -nop -exec bypass -EncodedCommand" nocase
    $poshdl0 = "IEX"
    $poshdl1 = "Net.Webclient"
    $poshdl2 = "DownloadString"
    $cmd0 = "cmd.exe /c echo %s > %s" nocase
  condition:
    $mz at 0 and (all of ($beacon*) or 3 of ($beaconcnc*) or all of ($posh*) or all of ($poshdl*) or all of ($cmd*))
}
