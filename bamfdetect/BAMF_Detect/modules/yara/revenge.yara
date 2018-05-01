rule revengerat {
  meta:
    description = "Revenge RAT"
    author = "Paul Melson @pmelson"
    md5 = "f840760731e69b6c1676c8359c53f8b6"
  strings:
    $mz = { 4d 5a }
    $revconf1 = "*-]NK[-*" wide
    $revconf2 = "Revenge-RAT" wide
    $str1 = "RV_MUTEX" wide
    $str2 = "Select * from AntiVirusProduct" wide
    $str3 = "SELECT * FROM FirewallProduct" wide
    $str4 = "select * from Win32_Processor" wide
  condition:
    $mz at 0 and (all of ($revconf*) or all of ($str*))
}
