rule waketagat_xor_config {
    meta:
        author = "Paul Melson @pmelson"
        sha256 = "f4eb2a2caea341cf2e04838e8e369d9afbb34c641f5b18feab30583c37bbbdda"
        description = "Detect WAKETAGAT with 0xf XOR config"
    strings:
        // $useragent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)"
        $kernel32_dll = { 64 6a 7d 61 6a 63 3c 3d 21 6b 63 63 }
        $kernel32_GetModuleFileNameA = { 48 6a 7b 42 60 6b 7a 63 6a 49 66 63 6a 41 6e 62 6a 4e }
        $kernel32_MoveFileExA = { 42 60 79 6a 49 66 63 6a 4a 77 4e }
        $kernel32_CopyFileA = { 4c 60 7f 76 49 66 63 6a 4e }
        $kernel32_CreateFileA = { 4c 7d 6a 6e 7b 6a 49 66 63 6a 4e }
        $kernel32_GetFileSize = { 48 6a 7b 49 66 63 6a 5c 66 75 6a }
        $kernel32_VirtualAlloc = { 59 66 7d 7b 7a 6e 63 4e 63 63 60 6c }
        $kernel32_CloseHandle = { 4c 63 60 7c 6a 47 6e 61 6b 63 6a }
        $kernel32_ReadFile = { 5d 6a 6e 6b 49 66 63 6a }
        $kernel32_VirtualFree = { 59 66 7d 7b 7a 6e 63 49 7d 6a 6a }
        $kernel32_CreateProcessA = { 4c 7d 6a 6e 7b 6a 5f 7d 60 6c 6a 7c 7c 4e }
        $kernel32_GetThreadContext = { 48 6a 7b 5b 67 7d 6a 6e 6b 4c 60 61 7b 6a 77 7b }
        $kernel32_ReadProcessMemory = { 5d 6a 6e 6b 5f 7d 60 6c 6a 7c 7c 42 6a 62 60 7d 76 }
        $kernel32_VirtualAllocEx = { 59 66 7d 7b 7a 6e 63 4e 63 63 60 6c 4a 77 }
        $kernel32_WriteProcessMemory = { 58 7d 66 7b 6a 5f 7d 60 6c 6a 7c 7c 42 6a 62 60 7d 76 }
        $kernel32_SetThreadContext = { 5c 6a 7b 5b 67 7d 6a 6e 6b 4c 60 61 7b 6a 77 7b }
        $kernel32_TerminateProcess = { 5b 6a 7d 62 66 61 6e 7b 6a 5f 7d 60 6c 6a 7c 7c }
        $kernel32_ResumeThread = { 5d 6a 7c 7a 62 6a 5b 67 7d 6a 6e 6b }
        $kernel32_DeleteFileA = { 4b 6a 63 6a 7b 6a 49 66 63 6a 4e }
        $Ws2_32 = { 58 7c 3d 50 3c 3d 21 6b 63 63 }
        $Ws2_recv = { 00 7d 6a 6c 79 00 }
        $Ws2_send = { 00 7c 6a 61 6b 00 }
        $Ws2_htons = { 00 67 7b 60 61 7c 00 }
        $Ws2_connect = { 00 6c 60 61 61 6a 6c 7b 00 }
        $Ws2_socket = { 00 7c 60 6c 64 6a 7b 00 }
        $Ws2_gethostbyname = { 00 68 6a 7b 67 60 7c 7b 6d 76 61 6e 62 6a 00 }
        $Ws2_inet_addr = { 00 66 61 6a 7b 50 6e 6b 6b 7d 00 }
    condition:
        uint16(0) == 0x5a4d and (10 of ($kernel32*) or all of ($Ws2*))
}
