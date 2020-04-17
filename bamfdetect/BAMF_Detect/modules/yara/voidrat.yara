rule voidrat {
  strings:
    $str0 = "Invalid rootkey, could not be found." wide
    $str1 = "Could not open root registry keys, you may not have the needed permission" wide
    $str2 = "({0}:{1})" wide
    $str3 = "({0}:{1}:{2})" wide
    $str4 = "Key can not be empty." wide
    $str20 = "User: {0}{3}Pass: {1}{3}Host: {2}" wide
    $str21 = "[PRIVATE KEY LOCATION: \"{0}\"]" wide
    $str24 = "echo DONT CLOSE THIS WINDOW!" wide
    $str25 = "ping -n 10 localhost > nul" wide
    $quasar_salt = { bf eb 1e 56 fb cd 97 3b b2 19 02 24 30 a5 78 43 00 3d 56 44 d2 1e 62 b9 d4 f1 80 e7 e6 c3 39 41 }
  condition:
    4 of ($str*) and $quasar_salt
}

