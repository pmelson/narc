rule empire_loader {
  meta:
    author = "Paul Melson @pmelson"
    description = "detect PowerShell Empire scripts that load base64 encoded PE payloads"
    shoutout = "Thanks for coming to BSides Augusta 2019!"
  strings:
    $posh_refl = "System.Reflection.AssemblyName"
    $posh_frombase = "FromBase64String("
    // base64 encoded PE preambles
    $b64_pe00 = "TVqQAAMAAAAEAAAA"
    $b64_pe01 = "TVpQAAIAAAAEAA8A"
    $b64_pe02 = "TVoAAAAAAAAAAAAA"
    $b64_pe03 = "TVpBUlVIieVIgewg"
    $b64_pe04 = "TVqAAAEAAAAEABAA"
    $b64_pe05 = "TVroAAAAAFtSRVWJ"
    $b64_pe06 = "TVqQAAMABAAAAAAA"
    $b64_pe07 = "TVpBUlVIieVIgewgAAAA"
    $b64_pe08 = "TVpFUugAAAAAW0iD"
    // base64 encoded "his program can"
    // to catch "This program cannot be run in DOS mode." variations
    $b64_pe09 = "lzIHByb2dyY"
    $b64_pe10 = "pcyBwcm9ncm"
    $b64_pe11 = "aXMgcHJvZ3J"
  condition:
    #posh_refl == 2 and #posh_frombase == 1 and any of ($b64_pe*)
}
