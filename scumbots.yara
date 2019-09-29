rule posh_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "ascii and base64 encoded PowerShell artifacts, taken from the @ScumBots project"
  strings:
    $posh_search_term0 = "/c\"powershell" nocase
    $posh_search_term1 = "/c powershell" nocase
    $posh_search_term2 = "powershell -" nocase
    $posh_search_term3 = "powershell /" nocase
    $posh_search_term4 = "powershell.exe -" nocase
    $posh_search_term5 = "\\1.0\\powershell.exe" nocase
    $posh_search_term6 = "\\\\1.0\\\\powershell.exe" nocase
    $posh_search_term7 = "-runas32" nocase
    $posh_search_term8 = "::createthread" nocase
    $posh_search_term9 = " -bxor" nocase
    $posh_search_term10 = "[system.convert]::" nocase
    $posh_search_term11 = "frombase64string(" nocase
    $posh_search_term12 = "new-object system.io." nocase
    $posh_search_term13 = "[system.net." nocase
    $posh_search_term14 = "system.reflection.assemblyname" nocase
    $posh_search_term15 = "x509enrollment.cbinaryconverter" nocase
    $posh_search_term16 = "convertto-securestring" nocase
    $posh_base64_term0 = "93ZXJzaGVsb"
    $posh_base64_term1 = "d2Vyc2hlbGw"
    $posh_base64_term2 = "dlcnNoZWxs"
    $posh_base64_term3 = "8Ad2UAcnMAaGUAbG"
    $posh_base64_term4 = "b3cAZXIAc2gAZWw"
    $posh_base64_term5 = "8Ad2UAcnMAaGUAbG"
    $posh_base64_term6 = "93ZXJTaGVsb"
    $posh_base64_term7 = "d2VyU2hlbG"
    $posh_base64_term8 = "3dlclNoZWx"
    $posh_base64_term9 = "8Ad2UAclMAaGUAbG"
    $posh_base64_term10 = "3cAZXIAU2gAZWw"
    $posh_base64_term11 = "N5c3RlbS5Db252ZXJ0XT"
    $posh_base64_term12 = "eXN0ZW0uQ29udmVydF06O"
    $posh_base64_term13 = "lzdGVtLkNvbnZlcnRdO"
    $posh_base64_term14 = "MAeXMAdGUAbS4AQ28AbnYAZXIAdF0AO"
    $posh_base64_term15 = "AHlzAHRlAG0uAENvAG52AGVyAHRdAD"
    $posh_base64_term16 = "B5cwB0ZQBtLgBDbwBudgBlcgB0XQ"
    $posh_base64_term17 = "JvbUJhc2U2N"
    $posh_base64_term18 = "b21CYXNlNj"
    $posh_base64_term19 = "cm9tQmFzZTY"
    $posh_base64_term20 = "IAb20AQmEAc2UAN"
    $posh_base64_term21 = "AG9tAEJhAHNlADY0"
    $posh_base64_term22 = "gBvbQBCYQBzZQA2"
    $posh_base64_term23 = "V3LU9iamVjdCBTeXN0ZW0uSU"
    $posh_base64_term24 = "ldy1PYmplY3QgU3lzdGVtLklP"
    $posh_base64_term25 = "ZXctT2JqZWN0IFN5c3RlbS5JT"
    $posh_base64_term26 = "UAdy0AT2IAamUAY3QAIFMAeXMAdGUAbS4ASU8"
    $posh_base64_term27 = "lAHctAE9iAGplAGN0ACBTAHlzAHRlAG0uAElPA"
    $posh_base64_term28 = "ZQB3LQBPYgBqZQBjdAAgUwB5cwB0ZQBtLgBJ"
    $posh_base64_term29 = "N5c3RlbS5OZX"
    $posh_base64_term30 = "TeXN0ZW0uTmV0"
    $posh_base64_term31 = "U3lzdGVtLk5ld"
    $posh_base64_term32 = "MAeXMAdGUAbS4ATmUAd"
    $posh_base64_term33 = "TAHlzAHRlAG0uAE5lAH"
    $posh_base64_term34 = "UwB5cwB0ZQBtLgBOZQB0"
    $posh_base64_term35 = "lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHlO"
    $posh_base64_term36 = "5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFt"
    $posh_base64_term37 = "XN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseU5hb"
    $posh_base64_term38 = "kAc3QAZW0ALlIAZWYAbGUAY3QAaW8Abi4AQXMAc2UAbWIAbHkATmE"
    $posh_base64_term39 = "5AHN0AGVtAC5SAGVmAGxlAGN0AGlvAG4uAEFzAHNlAG1iAGx5AE5hAG"
    $posh_base64_term40 = "QBzdABlbQAuUgBlZgBsZQBjdABpbwBuLgBBcwBzZQBtYgBseQBOYQBt"
    $posh_base64_term41 = "pDcmVhdGVUaHJlY"
    $posh_base64_term42 = "6Q3JlYXRlVGhyZW"
    $posh_base64_term43 = "kNyZWF0ZVRocmVh"
    $posh_base64_term44 = "oAQ3IAZWEAdGUAVGgAcmUAY"
    $posh_base64_term45 = "AENyAGVhAHRlAFRoAHJlAG"
    $posh_base64_term46 = "gBDcgBlYQB0ZQBUaAByZQB"
    $posh_base64_term47 = "UwOUVucm9sbG1lbnQuQ0JpbmFyeUNvbnZlcnR"
    $posh_base64_term48 = "1MDlFbnJvbGxtZW50LkNCaW5hcnlDb252ZXJ0Z"
    $posh_base64_term49 = "NTA5RW5yb2xsbWVudC5DQmluYXJ5Q29udmVydG"
    $posh_base64_term50 = "UAMDkARW4Acm8AbGwAbWUAbnQALkMAQmkAbmEAcnkAQ28AbnYAZXIAdG"
    $posh_base64_term51 = "1ADA5AEVuAHJvAGxsAG1lAG50AC5DAEJpAG5hAHJ5AENvAG52AGVyAHR"
    $posh_base64_term52 = "NQAwOQBFbgBybwBsbABtZQBudAAuQwBCaQBuYQByeQBDbwBudgBlcgB0"
    $posh_base64_term53 = "9udmVydFRvLVNlY3VyZVN0cmlu"
    $posh_base64_term54 = "vbnZlcnRUby1TZWN1cmVTdHJpb"
    $posh_base64_term55 = "b252ZXJ0VG8tU2VjdXJlU3RyaW"
    $posh_base64_term56 = "8AbnYAZXIAdFQAby0AU2UAY3UAcmUAU3QAcmkAb"
    $posh_base64_term57 = "vAG52AGVyAHRUAG8tAFNlAGN1AHJlAFN0AHJpAG"
    $posh_base64_term58 = "bwBudgBlcgB0VABvLQBTZQBjdQByZQBTdAByaQB"
    $posh_base64_term59 = "IC1ieG9y"
    $posh_base64_term60 = "AtYnhvcg"
    $posh_base64_term61 = "LWJ4b3I"
    $posh_base64_term62 = "IC0AYngAb3"
    $posh_base64_term63 = "tAGJ4AG9y"
    $posh_base64_term64 = "LQBieABvc"
  condition:
    any of them
}


rule dec_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "decimal encoded PE preambles, taken from the @ScumBots project"
  strings:
    $dec_search_term0 = "77 90 144 0 3 0 4 0"
    $dec_search_term1 = "77 90 232 0 0 0 0 91"
    $dec_search_term2 = "77 90 144 0 3 0 0 0"
    $dec_search_term3 = "77 90 80 0 2 0 0 0"
    $dec_search_term4 = "77 90 0 0 0 0 0 0"
    $dec_search_term5 = "77 90 65 82 85 72 137 229"
    $dec_search_term6 = "77 90 128 0 1 0 0 0"
    $dec_search_term7 = "77,90,144,0,3,0,4,0,"
    $dec_search_term8 = "77,90,232,0,0,0,0,91,"
    $dec_search_term9 = "77,90,144,0,3,0,0,0,"
    $dec_search_term10 = "77,90,80,0,2,0,0,0,"
    $dec_search_term11 = "77,90,0,0,0,0,0,0,"
    $dec_search_term12 = "77,90,65,82,85,72,137,229,"
    $dec_search_term13 = "77,90,128,0,1,0,0,0,"
    $dec_search_term14 = "77, 90, 144, 0, 3, 0, 4, 0,"
    $dec_search_term15 = "77, 90, 232, 0, 0, 0, 0, 91,"
    $dec_search_term16 = "77, 90, 144, 0, 3, 0, 0, 0,"
    $dec_search_term17 = "77, 90, 80, 0, 2, 0, 0, 0,"
    $dec_search_term18 = "77, 90, 0, 0, 0, 0, 0, 0,"
    $dec_search_term19 = "77, 90, 65, 82, 85, 72, 137, 229,"
    $dec_search_term20 = "77, 90, 128, 0, 1, 0, 0, 0,"
  condition:
    any of them
}


rule bin_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "binary encoded PE preambles, taken from the @ScumBots project"
  strings:
    $bin_search_term0 = "010011010101101000000000000000000000000000000000"
    $bin_search_term1 = "010011010101101001000001010100100101010101001000"
    $bin_search_term2 = "010011010101101001010000000000000000001000000000"
    $bin_search_term3 = "010011010101101010000000000000000000000100000000"
    $bin_search_term4 = "010011010101101010010000000000000000001100000000"
    $bin_search_term5 = "010011010101101011101000000000000000000000000000"
    $bin_search_term6 = "0100 1101 0101 1010 0000 0000 0000 0000 0000 0000 0000 0000"
    $bin_search_term7 = "0100 1101 0101 1010 0100 0001 0101 0010 0101 0101 0100 1000"
    $bin_search_term8 = "0100 1101 0101 1010 0101 0000 0000 0000 0000 0010 0000 0000"
    $bin_search_term9 = "0100 1101 0101 1010 1000 0000 0000 0000 0000 0001 0000 0000"
    $bin_search_term10 = "0100 1101 0101 1010 1001 0000 0000 0000 0000 0011 0000 0000"
    $bin_search_term11 = "0100 1101 0101 1010 1110 1000 0000 0000 0000 0000 0000 0000"
    $bin_search_term12 = "01 00 11 01 01 01 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    $bin_search_term13 = "01 00 11 01 01 01 10 10 01 00 00 01 01 01 00 10 01 01 01 01 01 00 10 00"
    $bin_search_term14 = "01 00 11 01 01 01 10 10 01 01 00 00 00 00 00 00 00 00 00 10 00 00 00 00"
    $bin_search_term15 = "01 00 11 01 01 01 10 10 10 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00"
    $bin_search_term16 = "01 00 11 01 01 01 10 10 10 01 00 00 00 00 00 00 00 00 00 11 00 00 00 00"
    $bin_search_term17 = "01 00 11 01 01 01 10 10 11 10 10 00 00 00 00 00 00 00 00 00 00 00 00 00"
  condition:
    any of them
}


rule base64_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "base64 encoded PE preambles and a couple PE header keywords, taken from the @ScumBots project"
  strings:
    $base64_search_term0 = "TVqQAAMAAAAEAAAA"
    $base64_search_term1 = "TVpQAAIAAAAEAA8A"
    $base64_search_term2 = "TVoAAAAAAAAAAAAA"
    $base64_search_term3 = "TVpBUlVIieVIgewg"
    $base64_search_term4 = "TVqAAAEAAAAEABAA"
    $base64_search_term5 = "TVroAAAAAFtSRVWJ"
    $base64_search_term6 = "TVqQAAMABAAAAAAA"
    $base64_search_term7 = "TVpBUlVIieVIgewgAAAA"
    $base64_search_term8 = "TVpFUugAAAAAW0iD"
    $base64_search_term9 = "kJCQkE1aQVJVSInlSIHsIAAAA"
    $base64_search_term10 = "pcyBwcm9ncm"
    $base64_search_term11 = "lzIHByb2dyY"
    $base64_search_term12 = "aXMgcHJvZ3J"
  condition:
    any of them
}


rule doublebase_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "two rounds of base64 encoding of PE preambles, taken from the @ScumBots project"
  strings:
    $double_search_term0 = "VFZxUUFBTUFBQUFFQUFBQ"
    $double_search_term1 = "VFZwUUFBSUFBQUFFQUE4Q"
    $double_search_term2 = "VFZvQUFBQUFBQUFBQUFBQ"
    $double_search_term3 = "VFZwQlVsVklpZVZJZ2V3Z"
    $double_search_term4 = "VFZxQUFBRUFBQUFFQUJBQ"
    $double_search_term5 = "VFZyb0FBQUFBRnRTUlZXS"
    $double_search_term6 = "VFZxUUFBTUFCQUFBQUFBQ"
  condition:
    any of them
}


rule doublewidebase_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "two rounds of base64 encoding with one round of null padding, taken from the @ScumBots project"
  strings:
    $doublewide_search_term0 = "VABWAHEAUQBBAEEATQBBAEEAQQBBAEUAQQBBAEEAQQ"
    $doublewide_search_term1 = "VABWAHAAUQBBAEEASQBBAEEAQQBBAEUAQQBBADgAQQ"
    $doublewide_search_term2 = "VABWAG8AQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQ"
    $doublewide_search_term3 = "VABWAHAAQgBVAGwAVgBJAGkAZQBWAEkAZwBlAHcAZw"
    $doublewide_search_term4 = "VABWAHEAQQBBAEEARQBBAEEAQQBBAEUAQQBCAEEAQQ"
    $doublewide_search_term5 = "VABWAHIAbwBBAEEAQQBBAEEARgB0AFMAUgBWAFcASg"
    $doublewide_search_term6 = "VABWAHEAUQBBAEEATQBBAEIAQQBBAEEAQQBBAEEAQQ"
    $doublewide_search_term7 = "VABWAHAAQgBVAGwAVgBJAGkAZQBWAEkAZwBlAHcAZwBBAEEAQQ"
    $doublewide_search_term8 = "awBKAEMAUQBrAEUAMQBhAFEAVgBKAFYAUwBJAG4AbABTAEkASABzAEkAQQBBAEEAQQ"
  condition:
    any of them
}


rule exe_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "raw PE preamble byte sequences, taken from the @ScumBots project"
  strings:
    $exe_search_terms0 = { 4d 5a 90 00 03 00 00 00 } 
    $exe_search_terms1 = { 4d 5a 50 00 02 00 00 00 }
    $exe_search_terms2 = { 4d 5a 00 00 00 00 00 00 } 
    $exe_search_terms3 = { 4d 5a 41 52 55 48 89 e5 } 
    $exe_search_terms4 = { 4d 5a 80 00 01 00 00 00 } 
    $exe_search_terms5 = { 4d 5a 90 00 03 00 04 00 } 
    $exe_search_terms6 = { 4d 5a e8 00 00 00 00 5b }
  condition:
    any of them
}


rule hex_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "hex encoded PE preambles, taken from the @ScumBots project"
  strings:
    $hex_search_term0 = "4d5a900003000000" nocase
    $hex_search_term1 = "4d5a500002000000" nocase
    $hex_search_term2 = "4d5a000000000000" nocase
    $hex_search_term3 = "4d5a4152554889e5" nocase
    $hex_search_term4 = "4d5a800001000000" nocase
    $hex_search_term5 = "4d5a900003000400" nocase
    $hex_search_term6 = "4d5ae8000000005b" nocase
    $hex_pe_regex = /4d[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}5a[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|41|50|80|90|e8)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|52)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|01|02|03|55)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|48)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|04|89)[\ 0x\:\;&\{\}\|\*\.\/\$\^\-%,()!+<>\?#@]{1,5}(00|5b|e5)/ nocase
  condition:
    any of them
}


rule hexbase_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are base64 encoded then hex encoded, plus spacing, taken from the @ScumBots project"
  strings:
    $hexbase_search_term0 = "5456715141414d414141414541414141" nocase
    $hexbase_search_term1 = "54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41" nocase
    $hexbase_search_term2 = "54567051414149414141414541413841" nocase
    $hexbase_search_term3 = "54 56 70 51 41 41 49 41 41 41 41 45 41 41 38 41" nocase
    $hexbase_search_term4 = "54566f41414141414141414141414141" nocase
    $hexbase_search_term5 = "54 56 6f 41 41 41 41 41 41 41 41 41 41 41 41 41" nocase
    $hexbase_search_term6 = "54567042556c56496965564967657767" nocase
    $hexbase_search_term7 = "54 56 70 42 55 6c 56 49 69 65 56 49 67 65 77 67" nocase
    $hexbase_search_term8 = "54567141414145414141414541424141" nocase
    $hexbase_search_term9 = "54 56 71 41 41 41 45 41 41 41 41 45 41 42 41 41" nocase
    $hexbase_search_term10 = "5456726f41414141414674535256574a" nocase
    $hexbase_search_term11 = "54 56 72 6f 41 41 41 41 41 46 74 53 52 56 57 4a" nocase
    $hexbase_search_term12 = "5456715141414d414241414141414141" nocase
    $hexbase_search_term13 = "54 56 71 51 41 41 4d 41 42 41 41 41 41 41 41 41" nocase
  condition:
    any of them
}
    

rule basehex_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are binary encoded (plus spacing) then base64 encoded, taken from the @ScumBots project"
  strings:
    $basehex_search_term0 = "NGQ1YTkwMDAwMzAwMDAwMA"
    $basehex_search_term1 = "NEQ1QTkwMDAwMzAwMDAwMA"
    $basehex_search_term2 = "NGQ1YTUwMDAwMjAwMDAwMA"
    $basehex_search_term3 = "NEQ1QTUwMDAwMjAwMDAwMA"
    $basehex_search_term4 = "NGQ1YTAwMDAwMDAwMDAwMA"
    $basehex_search_term5 = "NEQ1QTAwMDAwMDAwMDAwMA"
    $basehex_search_term6 = "NGQ1YTQxNTI1NTQ4ODllNQ"
    $basehex_search_term7 = "NEQ1QTQxNTI1NTQ4ODlFNQ"
    $basehex_search_term8 = "NGQ1YTgwMDAwMTAwMDAwMA"
    $basehex_search_term9 = "NEQ1QTgwMDAwMTAwMDAwMA"
    $basehex_search_term10 = "NGQ1YTkwMDAwMzAwMDQwMA"
    $basehex_search_term11 = "NEQ1QTkwMDAwMzAwMDQwMA"
    $basehex_search_term12 = "NGQ1YWU4MDAwMDAwMDA1Yg"
    $basehex_search_term13 = "NEQ1QUU4MDAwMDAwMDA1Qg"
    $basehex_search_term14 = "NGQgNWEgOTAgMDAgMDMgMDAgMDQgMDA"
    $basehex_search_term15 = "NEQgNUEgOTAgMDAgMDMgMDAgMDQgMDA"
    $basehex_search_term16 = "NGQgNWEgZTggMDAgMDAgMDAgMDAgNWI"
    $basehex_search_term17 = "NEQgNUEgRTggMDAgMDAgMDAgMDAgNUI"
    $basehex_search_term18 = "NGQgNWEgOTAgMDAgMDMgMDAgMDAgMDA"
    $basehex_search_term19 = "NEQgNUEgOTAgMDAgMDMgMDAgMDAgMDA"
    $basehex_search_term20 = "NGQgNWEgNTAgMDAgMDIgMDAgMDAgMDA"
    $basehex_search_term21 = "NEQgNUEgNTAgMDAgMDIgMDAgMDAgMDA"
    $basehex_search_term22 = "NGQgNWEgMDAgMDAgMDAgMDAgMDAgMDA"
    $basehex_search_term23 = "NEQgNUEgMDAgMDAgMDAgMDAgMDAgMDA"
    $basehex_search_term24 = "NGQgNWEgNDEgNTIgNTUgNDggODkgZTU"
    $basehex_search_term25 = "NEQgNUEgNDEgNTIgNTUgNDggODkgRTU"
    $basehex_search_term26 = "NGQgNWEgODAgMDAgMDEgMDAgMDAgMDA"
    $basehex_search_term27 = "NEQgNUEgODAgMDAgMDEgMDAgMDAgMDA"
    $basehex_search_term28 = "NGQgNWEgOTAgMDAgMDMgMDAgMDQgMDA"
    $basehex_search_term29 = "NEQgNUEgOTAgMDAgMDMgMDAgMDQgMDA"
    $basehex_search_term30 = "NGQgNWEgZTggMDAgMDAgMDAgMDAgNWI"
    $basehex_search_term31 = "NEQgNUEgRTggMDAgMDAgMDAgMDAgNUI"
    $basehex_search_term32 = "MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg"
    $basehex_search_term33 = "MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg"
    $basehex_search_term34 = "MHg0ZCwweDVhLDB4ZTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDViCg"
    $basehex_search_term35 = "MHg0RCwweDVBLDB4RTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDVCCg"
    $basehex_search_term36 = "MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term37 = "MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term38 = "MHg0ZCwweDVhLDB4NTAsMHgwMCwweDAyLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term39 = "MHg0RCwweDVBLDB4NTAsMHgwMCwweDAyLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term40 = "MHg0ZCwweDVhLDB4MDAsMHgwMCwweDAwLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term41 = "MHg0RCwweDVBLDB4MDAsMHgwMCwweDAwLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term42 = "MHg0ZCwweDVhLDB4NDEsMHg1MiwweDU1LDB4NDgsMHg4OSwweGU1Cg"
    $basehex_search_term43 = "MHg0RCwweDVBLDB4NDEsMHg1MiwweDU1LDB4NDgsMHg4OSwweEU1Cg"
    $basehex_search_term44 = "MHg0ZCwweDVhLDB4ODAsMHgwMCwweDAxLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term45 = "MHg0RCwweDVBLDB4ODAsMHgwMCwweDAxLDB4MDAsMHgwMCwweDAwCg"
    $basehex_search_term46 = "MHg0ZCwweDVhLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg"
    $basehex_search_term47 = "MHg0RCwweDVBLDB4OTAsMHgwMCwweDAzLDB4MDAsMHgwNCwweDAwCg"
    $basehex_search_term48 = "MHg0ZCwweDVhLDB4ZTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDViCg"
    $basehex_search_term49 = "MHg0RCwweDVBLDB4RTgsMHgwMCwweDAwLDB4MDAsMHgwMCwweDVCCg"
  condition:
    any of them
}


rule hexbin_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are binary encoded then hex encoded, plus spacing, taken from the @ScumBots project"
  strings:
    $hexbin_search_term0 = "303130303131303130313031313031303030303030303030303030303030303030303030303030303030303030303030"
    $hexbin_search_term1 = "303130303131303130313031313031303031303030303031303130313030313030313031303130313031303031303030"
    $hexbin_search_term2 = "303130303131303130313031313031303031303130303030303030303030303030303030303031303030303030303030"
    $hexbin_search_term3 = "303130303131303130313031313031303130303030303030303030303030303030303030303030313030303030303030"
    $hexbin_search_term4 = "303130303131303130313031313031303130303130303030303030303030303030303030303031313030303030303030"
    $hexbin_search_term5 = "303130303131303130313031313031303131313031303030303030303030303030303030303030303030303030303030"
    $hexbin_search_term6 = "30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30"
    $hexbin_search_term7 = "30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 31 30 30 30 30 30 31 30 31 30 31 30 30 31 30 30 31 30 31 30 31 30 31 30 31 30 30 31 30 30 30"
    $hexbin_search_term8 = "30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 30 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 30"
    $hexbin_search_term9 = "30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30"
    $hexbin_search_term10 = "30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 30 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 31 30 30 30 30 30 30 30 30"
    $hexbin_search_term11 = "30 31 30 30 31 31 30 31 30 31 30 31 31 30 31 30 31 31 31 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30"
  condition:
    any of them
}


rule basebin_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are binary encoded (plus spacing) then base64 encoded, taken from the @ScumBots project"
  strings:
    $basebin_search_term0 = "MDEwMDExMDEwMTAxMTAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
    $basebin_search_term1 = "MDEwMDExMDEwMTAxMTAxMDAxMDAwMDAxMDEwMTAwMTAwMTAxMDEwMTAxMDAxMDAw"
    $basebin_search_term2 = "MDEwMDExMDEwMTAxMTAxMDAxMDEwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDAw"
    $basebin_search_term3 = "MDEwMDExMDEwMTAxMTAxMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAw"
    $basebin_search_term4 = "MDEwMDExMDEwMTAxMTAxMDEwMDEwMDAwMDAwMDAwMDAwMDAwMDAxMTAwMDAwMDAw"
    $basebin_search_term5 = "MDEwMDExMDEwMTAxMTAxMDExMTAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
    $basebin_search_term6 = "MDEwMCAxMTAxIDAxMDEgMTAxMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAw"
    $basebin_search_term7 = "MDEwMCAxMTAxIDAxMDEgMTAxMCAwMTAwIDAwMDEgMDEwMSAwMDEwIDAxMDEgMDEwMSAwMTAwIDEw"
    $basebin_search_term8 = "MDEwMCAxMTAxIDAxMDEgMTAxMCAwMTAxIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAxMCAwMDAwIDAw"
    $basebin_search_term9 = "MDEwMCAxMTAxIDAxMDEgMTAxMCAxMDAwIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMSAwMDAwIDAw"
    $basebin_search_term10 = "MDEwMCAxMTAxIDAxMDEgMTAxMCAxMDAxIDAwMDAgMDAwMCAwMDAwIDAwMDAgMDAxMSAwMDAwIDAw"
    $basebin_search_term11 = "MDEwMCAxMTAxIDAxMDEgMTAxMCAxMTEwIDEwMDAgMDAwMCAwMDAwIDAwMDAgMDAwMCAwMDAwIDAw"
    $basebin_search_term12 = "MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMD"
    $basebin_search_term13 = "MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDEgMDAgMDAgMDEgMDEgMDEgMDAgMTAgMDEgMDEgMDEgMDEgMDEgMDAgMTAgMD"
    $basebin_search_term14 = "MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMDEgMDEgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMTAgMDAgMDAgMDAgMD"
    $basebin_search_term15 = "MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDEgMDAgMDAgMDAgMD"
    $basebin_search_term16 = "MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTAgMDEgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMTEgMDAgMDAgMDAgMD"
    $basebin_search_term17 = "MDEgMDAgMTEgMDEgMDEgMDEgMTAgMTAgMTEgMTAgMTAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMDAgMD"
  condition:
    any of them
}


rule basegzip_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are gzip compressed (with headers) then base64 encoded, taken from the @ScumBots project"
  strings:
    $basegzip_search_term0 = "H4sIAAAAAAAEAO18"
    $basegzip_search_term1 = "H4sIAAAAAAAEAO19"
    $basegzip_search_term2 = "H4sIAAAAAAAEAOy9"
    $basegzip_search_term3 = "H4sIAAAAAAAEAO29"
    $basegzip_search_term4 = "H4sIAAAAAAAEAOS9"
    $basegzip_search_term5 = "H4sIAAAAAAAEAOy8"
    $basegzip_search_term6 = "H4sIAAAAAAAEAOx9"
    $basegzip_search_term7 = "H4sIAAAAAAAEAO17"
    $basegzip_search_term8 = "H4sIAAAAAAAEAMy9"
  condition:
    any of them
}


rule baserot_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are base64 encoded then rot13 encoded, taken from the @ScumBots project"
  strings:
    $baserot_search_term0 = "GIdDNNZNNNNRNNNN"
    $baserot_search_term1 = "GIcDNNVNNNNRNN8N"
    $baserot_search_term2 = "GIbNNNNNNNNNNNNN"
    $baserot_search_term3 = "GIcOHyIVvrIVtrjt"
    $baserot_search_term4 = "GIdNNNRNNNNRNONN"
    $baserot_search_term5 = "GIebNNNNNSgFEIJW"
    $baserot_search_term6 = "GIdDNNZNONNNNNNN"
    $baserot_search_term7 = "GIcOHyIVvrIVtrjtNNNN"
  condition:
    any of them
}


rule base64_doc {
  meta:
    author = "Paul Melson @pmelson"
    description = "when common Office file formats are base64 encoded, taken from the @ScumBots project"
  strings:
    $basedoc_search_term0 = "0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA"
    $basedoc_search_term1 = "UEsDBBQABgAIAAAAIQ"
    $basedoc_search_term2 = "UEsDBBQACAAIAAAAAA"
    $basedoc_search_term3 = "e1xydGYxXGFkZWZsYW5nMTAy"
    $basedoc_search_term4 = "e1xydGYxXGFuc2lcYW5zaWNw"
    $basedoc_search_term5 = "e1xydGYxB25zaQduc2ljcGcx"
    $basedoc_search_term6 = "e1xydGYxDQogSGVyZSBhcmUg"
    $basedoc_search_term7 = "e1xydGYxe1xvYmplY3Rcb2Jq"
    $basedoc_search_term8 = "e1xydGZ7XG9iamVjdFxvYmpo"
  condition:
    any of them
}


rule gzencode_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "when PE preambles are gzip compressed (no headers) then base64 encoded, taken from the @ScumBots project"
  strings:
    $gzencode_search_term0 = "7b0HYBxJliUmL2"
    $gzencode_search_term1 = "cG93ZXJzaGVsbC"
    $gzencode_search_term2 = "UG93ZXJTaGVsbC"
    $gzencode_search_term3 = "tL0HfFzFET/+7t"
    $gzencode_search_term4 = "7XwJdFxXkWi9pd"
    $gzencode_search_term5 = "7XsLdBzVleCtqu"
    $gzencode_search_term6 = "7b15fBzFsTheM7"
  condition:
    any of them
}


rule basethreetwelve_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "PE preambles base64 encoded then decimal encoded plus 312, taken from the @ScumBots project"
  strings:
    $base312_search_term0 = "396 398 425 393 377 377 389 377 377 377 377 381 377 377 377 377"
    $base312_search_term1 = "396 398 424 393 377 377 385 377 377 377 377 381 377 377 368 377"
    $base312_search_term2 = "396 398 423 377 377 377 377 377 377 377 377 377 377 377 377 377"
    $base312_search_term3 = "396 398 424 378 397 420 398 385 417 413 398 385 415 413 431 415"
    $base312_search_term4 = "396 398 425 377 377 377 381 377 377 377 377 381 377 378 377 377"
    $base312_search_term5 = "396 398 426 423 377 377 377 377 377 382 428 395 394 398 399 386"
    $base312_search_term6 = "396 398 425 393 377 377 389 377 378 377 377 377 377 377 377 377"
    $base312_search_term7 = "396 398 424 378 397 420 398 385 417 413 398 385 415 413 431 415 377 377 377 377"
    $base312_search_term8 = "419 386 379 393 419 381 361 409 393 398 386 398 395 385 422 420 395 385 384 427 385 377 377 377 377"
  condition:
    any of them
}


rule basebash_find {
  meta:
    author = "Paul Melson @pmelson"
    description = "indicators of bash or python scripts that have been base64 encoded, taken from the @ScumBots project"
  strings:
    $basebase_search_term0 = "IyEvYmluL2Jhc2"
    $basebase_search_term1 = "IyEvYmluL3No"
    $basebase_search_term2 = "L2Jpbi9iYXNo"
    $basebase_search_term3 = "L2Jpbi9za"
    $basebase_search_term4 = "IyEgL3Vzci9iaW4vZW52IHB5dGhvb"
    $basebase_search_term5 = "IyEvdXNyL2Jpbi9lbnYgcHl0aG9"
    $basebase_search_term6 = "IyEvdXNyL2Jpbi9weXRob2"
  condition:
    any of them
}
