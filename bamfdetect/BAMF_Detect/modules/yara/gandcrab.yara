rule gandcrab {
  meta:
    author = "Paul Melson @pmelson"
    description = "Detect unpacked GandCrab ransomware"
  strings:
    $artifact0 = "KRAB-DECRYPT.html" wide
    $artifact1 = "KRAB-DECRYPT.txt" wide
    $artifact2 = "CRAB-DECRYPT.txt" wide
    $artifact3 = "%s\\KRAB-DECRYPT.txt" wide
    $artifact4 = "%s.KRAB" wide
    $artifact5 = "%s%x%x%x%x.lock" wide
    $artifact6 = "http://memesmix.net/media/created/dd0doq.jpg" wide
    $proc0 = "cmd.exe" wide
    $proc1 = "msftesql.exe" wide
    $proc2 = "sqlagent.exe" wide
    $proc3 = "sqlbrowser.exe" wide
    $proc4 = "sqlwriter.exe" wide
    $proc5 = "oracle.exe" wide
    $proc6 = "ocssd.exe" wide
    $proc7 = "dbsnmp.exe" wide
    $proc8 = "synctime.exe" wide
    $proc9 = "agntsvc.exe" wide
    $proc10 = "sqlplussvc.exe" wide
    $proc11 = "xfssvccon.exe" wide
    $proc12 = "sqlservr.exe" wide
    $proc13 = "mydesktopservice.exe" wide
    $proc14 = "ocautoupds.exe" wide
    $proc15 = "agntsvc.exe" wide
    $proc16 = "firefoxconfig.exe" wide
    $proc17 = "tbirdconfig.exe" wide
    $proc18 = "mydesktopqos.exe" wide
    $proc19 = "ocomm.exe" wide
    $proc20 = "mysqld.exe" wide
    $proc21 = "mysqld-nt.exe" wide
    $proc22 = "mysqld-opt.exe" wide
    $proc23 = "dbeng50.exe" wide
    $proc24 = "sqbcoreservice.exe" wide
    $proc25 = "excel.exe" wide
    $proc26 = "infopath.exe" wide
    $proc27 = "msaccess.exe" wide
    $proc28 = "mspub.exe" wide
    $proc29 = "onenote.exe" wide
    $proc30 = "outlook.exe" wide
    $proc31 = "powerpnt.exe" wide
    $proc32 = "steam.exe" wide
    $proc33 = "thebat.exe" wide
    $proc34 = "thebat64.exe" wide
    $proc35 = "thunderbird.exe" wide
    $proc36 = "visio.exe" wide
    $proc37 = "winword.exe" wide
    $proc38 = "wordpad.exe" wide
    $proc39 = "AVP.EXE" wide
    $proc40 = "ekrn.exe" wide
    $proc41 = "avgnt.exe" wide
    $proc42 = "ashDisp.exe" wide
    $proc43 = "NortonAntiBot.exe" wide
    $proc44 = "Mcshield.exe" wide
    $proc45 = "avengine.exe" wide
    $proc46 = "cmdagent.exe" wide
    $proc47 = "smc.exe" wide
    $proc48 = "persfw.exe" wide
    $proc49 = "pccpfw.exe" wide
    $proc50 = "fsguiexe.exe" wide
    $proc51 = "cfp.exe" wide
    $proc52 = "msmpeng.exe" wide
    $var0 = "public" wide
    $var1 = "private" wide
    $var2 = "ransom_id" wide
    $var3 = "os_bit" wide
    $var4 = "os_major" wide
    $var5 = "pc_keyb" wide
    $var6 = "pc_lang" wide
    $var7 = "pc_group" wide
    $var8 = "pc_name" wide
    $var9 = "pc_user" wide
    $var10 = "ransom_id=" wide
    $var11 = "&id=" wide
    $var12 = "&sub_id=" wide
    $var13 = "1&version=" wide
    $var14 = "&action=call" wide
  condition:
    uint16(0) == 0x5a4d and (any of ($artifact*) or all of ($proc*) or all of ($var*))
}
