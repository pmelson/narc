rule meterpreter {
  meta:
    description = "Find Windows PE, DLL, or assembly versions of Meterpreter"
    author = "Paul Melson @pmelson"
  strings:
    $func0 = "core_loadlib"
    $func1 = "core_enumextcmd"
    $func2 = "core_machine_id"
    $func3 = "core_get_session_guid"
    $func4 = "core_set_session_guid"
    $func5 = "core_set_uuid"
    $func6 = "core_pivot_add"
    $func7 = "core_pivot_remove"
    $func8 = "core_patch_url"
  condition:
    uint16(0) == 0x5a4d and 4 of ($func*)
}

