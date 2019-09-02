rule meterpreterx86 {
  meta:
    description = "Find PE files with Meterpreter x86 TCP callback shellcode bytes"
    author = "Paul Melson @pmelson"
  strings:
    $shellstub = { fc e8 82 00 00 00 60 89 }
    $config = { 00 ff d5 6a ( 0a | 01 ) 68 [4] 68 02 00 [2] 89 e6 50 50 }
  condition:
    uint16be(0) == 0x4d5a and all of them
}
