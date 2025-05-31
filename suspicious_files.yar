rule Suspicious_File_Detector
{
    meta:
        author = "DFIR Analyst"
        description = "Detects suspicious or potentially malicious files"
        created = "2025-05-31"

    strings:
        // Suspicious API calls
        $api1 = "VirtualAlloc"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "GetProcAddress"
        $api5 = "LoadLibraryA"

        // Obfuscation indicators
        $base64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $hex_encoding = /\\x[0-9a-fA-F]{2}/

        // Suspicious file or registry references
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $temp_path = "C:\\\\Users\\\\%USERNAME%\\\\AppData\\\\Local\\\\Temp"

        // Malware keywords
        $keylogger = "keylog"
        $persistence = "schtasks"
        $cmd_exec = "cmd.exe /c"
        $powershell = "powershell -exec bypass"

    condition:
        // Trigger if any 3 or more suspicious indicators found
        3 of ($api*) or
        2 of ($reg1, $temp_path, $persistence, $cmd_exec, $powershell) or
        $base64 or $hex_encoding
}
