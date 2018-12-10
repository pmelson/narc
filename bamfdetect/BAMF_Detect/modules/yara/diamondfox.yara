rule diamond_fox
{
    strings:
    	$s1 = "UPDATE_B"
        $s2 = "UNISTALL_B"
        $s3 = "S_PROTECT"
        $s4 = "P_WALLET"
        $s5 = "GR_COMMAND"
        $s6 = "FTPUPLOAD"
        $s0 = "loader.exe"
        $s18 = "Melt.bat"
        $s19 = "<Panel>" wide
        $s20 = "VM_WINXP" wide
        $s21 = "plugins/keylogger.p" wide
        $s22 = "</ABox>" wide
        $s23 = "winmgmts:{impersonationlevel=impersonate}!\\\\\\\\.\\\\root\\\\$"
        $s7 = "<Time>" wide
        $s8 = "MY_PATH"
        $s9 = "cript.Sleep(2000)"
        $s10 = "</Boxie>" wide
        $s11 = "SHELL32"
        $s12 = "& chr(34)" wide
        $s13 = "</USB>" wide
        $s14 = "Shell.Application" wide
        $s15 = "CUSTOM" wide
        $s16 = "\\\\Armory\\\\" wide
        $s17 = "C_DATA"
    condition:
        6 of ($s*) and filesize<100KB
}
