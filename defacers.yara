rule encoded_defacer_kits {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect decimal or base64 encoded <php> or <html> tags"
  strings:
    $b64_html01 = "PGh0bWwK"
    $b64_html02 = "odG1sC"
    $b64_html03 = "8aHRtbA"
    $b64_php01 = "PHBocAo"
    $b64_php02 = "waHAK"
    $b64_php03 = "8cGhwC"
    $dec_html01 = "60, 104, 116, 109, 108"
    $dec_html02 = "60,104,116,109,108"
    $dec_html03 = "60 104 116 109 108"
    $dec_php01 = "60, 112, 104, 112"
    $dec_php02 = "60,112,104,112"
    $dec_php03 = "60 112 104 112"
  condition:
    (for any of ($dec*) : ($ in (0..100))) or
    (for any of ($b64*) : ($ in (0..100)))
}
