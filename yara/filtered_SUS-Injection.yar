rule Suspicious_Injection_Markers {
    meta:
        author = "Brentlyw"
        description = "Detect code injection and DLL reflection techniques"
        date = "2024-08-07"
        version = "1.0"

    strings:
        // Common API calls used in injection techniques
        $VirtualAlloc = "VirtualAlloc"
        $VirtualAllocEx = "VirtualAllocEx"
        $WriteProcessMemory = "WriteProcessMemory"
        $CreateRemoteThread = "CreateRemoteThread"
        $SetThreadContext = "SetThreadContext"
        $NtCreateThreadEx = "NtCreateThreadEx"
        $QueueUserAPC = "QueueUserAPC"
        $LoadLibrary = "LoadLibrary"
        $GetProcAddress = "GetProcAddress"
        $VirtualProtect = "VirtualProtect"
        $VirtualProtectEx = "VirtualProtectEx"

        // DLL reflection patterns
        $ReflectiveLoader = "ReflectiveLoader"
        $ReflectiveDLLInjection = "ReflectiveDLLInjection"
        $ReflectiveLoad = "ReflectiveLoad"
        $LoadLibraryR = "LoadLibraryR"
        $LoadLibraryA = "LoadLibraryA"
        $LoadLibraryW = "LoadLibraryW"
        $GetModuleHandleA = "GetModuleHandleA"
        $GetModuleHandleW = "GetModuleHandleW"
        $RtlCreateUserThread = "RtlCreateUserThread"

        // Shellcode markers
        $shellcode1 = {FC E8}
        $shellcode2 = {E8 00 00 00 00 58}
        $shellcode3 = {60 9C}
        $shellcode4 = {50 51 52 53 56 57 55 54}
        
        // Obfuscation patterns
        $obfuscation1 = "XOR"
        $obfuscation2 = "ROL"
        $obfuscation3 = "ROR"

    condition:
        2 of ($VirtualAlloc, $VirtualAllocEx, $WriteProcessMemory, $CreateRemoteThread, $SetThreadContext, $NtCreateThreadEx, $QueueUserAPC, $LoadLibrary, $GetProcAddress, $VirtualProtect, $VirtualProtectEx) or
        2 of ($ReflectiveLoader, $ReflectiveDLLInjection, $ReflectiveLoad, $LoadLibraryR, $LoadLibraryA, $LoadLibraryW, $GetModuleHandleA, $GetModuleHandleW, $RtlCreateUserThread) or
        2 of ($shellcode1, $shellcode2, $shellcode3, $shellcode4) or
        any of ($obfuscation1, $obfuscation2, $obfuscation3)
}
