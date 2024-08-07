rule Ping_Command_in_EXE {
   meta:
      description = "Detects an suspicious ping command execution in an executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2016-11-03"
      score = 60
      id = "937ab622-fbcf-5a31-a3ff-af2584484140"
   strings:
      $x1 = "cmd /c ping 127.0.0.1 -n " ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}
rule Suspicious_Script_Running_from_HTTP {
   meta:
      description = "Detects a suspicious "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
      score = 50
      date = "2017-08-20"
      id = "9ba84e9c-a32b-5f66-8d50-75344599cafc"
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition:
      1 of them
}
rule SUSP_LNK_File_AppData_Roaming {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 50
      id = "d905e58f-ae2e-5dc2-b206-d0435b023df0"
   strings:
      $s2 = "AppData" fullword wide
      $s3 = "Roaming" fullword wide
      /* .exe\x00C:\Users\ */
      $s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
              00 55 00 73 00 65 00 72 00 73 00 5C }
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         all of them
      )
}
rule SUSP_LNK_File_PathTraversal {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 40
      id = "f4f6709f-9c4d-5f0c-9826-97444d282adc"
   strings:
      $s1 = "..\\..\\..\\..\\..\\"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         all of them
      )
}
rule SUSP_Script_Obfuscation_Char_Concat {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
      id = "6d3bfdfd-ef8f-5740-ac1f-5835c7ce0f43"
   strings:
      $s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii
   condition:
      1 of them
}
rule SUSP_PowerShell_IEX_Download_Combo {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "13297f64a5f4dd9b08922c18ab100d3a3e6fdeab82f60a4653ab975b8ce393d5"
      id = "1dfedcb0-345c-548c-85ac-3c1e78bfd9e2"
   strings:
      $x1 = "IEX ((new-object net.webclient).download" ascii nocase

      $fp1 = "chocolatey.org"
      $fp2 = "Remote Desktop in the Appveyor"
      $fp3 = "/appveyor/" ascii
   condition:
      $x1 and not 1 of ($fp*)
}
rule SUSP_RAR_with_PDF_Script_Obfuscation {
   meta:
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-04-06"
      hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
      id = "a3d2f5e9-3052-551b-8b2c-abcdd1ac2e48"
   strings:
      $s1 = ".pdf.vbe" ascii
      $s2 = ".pdf.vbs" ascii
      $s3 = ".pdf.ps1" ascii
      $s4 = ".pdf.bat" ascii
      $s5 = ".pdf.exe" ascii
   condition:
      uint32(0) == 0x21726152 and 1 of them
}
rule SUSP_Netsh_PortProxy_Command {
   meta:
      description = "Detects a suspicious command line with netsh and the portproxy command"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
      date = "2019-04-20"
      score = 65
      hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
      id = "cbbd2042-572c-5283-bd45-e745b36733ad"
   strings:
      $x1 = "netsh interface portproxy add v4tov4 listenport=" ascii
   condition:
      1 of them
}
rule SUSP_PDB_Path_Keywords {
   meta:
      description = "Detects suspicious PDB paths"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
      date = "2019-10-04"
      id = "cbd9b331-58bb-5b29-88a2-5c19f12893a9"
   strings:
      $ = "Debug\\Shellcode" ascii
      $ = "Release\\Shellcode" ascii
      $ = "Debug\\ShellCode" ascii
      $ = "Release\\ShellCode" ascii
      $ = "Debug\\shellcode" ascii
      $ = "Release\\shellcode" ascii
      $ = "shellcode.pdb" nocase ascii
      $ = "\\ShellcodeLauncher" ascii
      $ = "\\ShellCodeLauncher" ascii
      $ = "Fucker.pdb" ascii
      $ = "\\AVFucker\\" ascii
      $ = "ratTest.pdb" ascii
      $ = "Debug\\CVE_" ascii
      $ = "Release\\CVE_" ascii
      $ = "Debug\\cve_" ascii
      $ = "Release\\cve_" ascii
   condition:
      uint16(0) == 0x5a4d and 1 of them
}
rule SUSP_Disable_ETW_Jun20_1 {
   meta:
      description = "Detects method to disable ETW in ENV vars before executing a program"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3"
      date = "2020-06-06"
      id = "ea5dee09-959e-5ef2-8f84-5497bdef0a05"
   strings:
      $x1 = "set COMPlus_ETWEnabled=0" ascii wide fullword
      $x2 = "$env:COMPlus_ETWEnabled=0" ascii wide fullword

      $s1 = "Software\\Microsoft.NETFramework" ascii wide
      $sa1 = "/v ETWEnabled" ascii wide fullword 
      $sa2 = " /d 0" ascii wide
      $sb4 = "-Name ETWEnabled"
      $sb5 = " -Value 0 "
   condition:
      1 of ($x*) or 3 of them 
}
rule SUSP_PE_Discord_Attachment_Oct21_1 {
   meta:
      description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-10-12"
      score = 70
      id = "7c217350-4a35-505d-950d-1bc989c14bc2"
   strings:
      $x1 = "https://cdn.discordapp.com/attachments/" ascii wide
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}
