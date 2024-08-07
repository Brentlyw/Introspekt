rule INDICATOR_EXE_Packed_ConfuserEx {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod"
        snort2_sid = "930016-930018"
        snort3_sid = "930005-930006"
    strings:
        $s1 = "ConfuserEx " ascii
        $s2 = "ConfusedByAttribute" fullword ascii
        $c1 = "Confuser.Core " ascii wide
        $u1 = "Confu v" fullword ascii
        $u2 = "ConfuByAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($c*) or all of ($u*))
}
rule INDICATOR_EXE_Packed_ConfuserEx_Custom {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Custom; outside of GIT"
    strings:
        $s1 = { 43 6f 6e 66 75 73 65 72 45 78 20 76 [1-2] 2e [1-2] 2e [1-2] 2d 63 75 73 74 6f 6d }
    condition:
        uint16(0) == 0x5a4d and all of them
}
rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod Beds Protector"
        snort2_sid = "930019-930024"
        snort3_sid = "930007-930008"
    strings:
        $s1 = "Beds Protector v" ascii
        $s2 = "Beds-Protector-v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_ConfuserExMod_Trinity {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
        snort2_sid = "930025-930030"
        snort3_sid = "930009-930010"
    strings:
        $s1 = "Trinity0-protecor|" ascii
        $s2 = "#TrinityProtector" fullword ascii
        $s3 = /Trinity\d-protector\|/ ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_PS2EXE {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with PS2EXE"
        snort2_sid = "930004-930006"
        snort3_sid = "930001"
    strings:
        $s1 = "PS2EXE" fullword ascii
        $s2 = "PS2EXEApp" fullword ascii
        $s3 = "PS2EXEHost" fullword ascii
        $s4 = "PS2EXEHostUI" fullword ascii
        $s5 = "PS2EXEHostRawUI" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_LSD {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with LSD packer"
        snort2_sid = "930058-930060"
        snort3_sid = "930021"
    strings:
        $s2 = "http://lsd.dg.com" ascii
        $s3 = "&V0LSD!$" fullword ascii
    condition:
         (uint16(0) == 0x5a4d or uint16(0)== 0x457f) and 1 of them
}
rule INDICATOR_EXE_Packed_AspireCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with AspireCrypt"
        snort2_sid = "930013-930015"
        snort3_sid = "930004"
    strings:
        $s1 = "AspireCrypt" fullword ascii
        $s2 = "aspirecrypt.net" ascii
        $s3 = "protected by AspireCrypt" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_Spices {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
        snort2_sid = "930001-930003"
        snort3_sid = "930000"
    strings:
        $s1 = "9Rays.Net Spices.Net" ascii
        $s2 = "protected by 9Rays.Net Spices.Net Obfuscator" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_JAVA_Packed_Allatori {
    meta:
        author = "ditekSHen"
    strings:
        $s1 = "# Obfuscation by Allatori Obfuscator" ascii wide
    condition:
        all of them
}
rule INDICATOR_EXE_Packed_aPLib {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with aPLib."
    strings:
        $header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }
    condition:
        ((uint32(0) == 0x32335041 and uint32(24) == 0x905a384d) or (uint16(0) == 0x5a4d and $header ))
}
rule INDICATOR_EXE_Packed_LibZ {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with LibZ"
        snort2_sid = "930055-930057"
        snort3_sid = "930019-930020"
    strings:
        $s1 = "LibZ.Injected" fullword ascii
        $s2 = "{0:N}.dll" fullword wide
        $s3 = "asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?" fullword wide
        $s4 = "Software\\Softpark\\LibZ" fullword wide
        $s5 = "(AsmZ/{" wide
        $s6 = "asmz://" ascii
        $s7 = "GetRegistryDWORD" ascii
        $s8 = "REGISTRY_KEY_NAME" fullword ascii
        $s9 = "REGISTRY_KEY_PATH" fullword ascii
        $s10 = "InitializeDecoders" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
rule INDICATOR_MSI_EXE2MSI {
    meta:
        author = "ditekSHen"
        description = "Detects executables converted to .MSI packages using a free online converter."
        snort2_sid = "930061-930063"
        snort3_sid = "930022"
    strings:
        $winin = "Windows Installer" ascii
        $title = "Exe to msi converter free" ascii
    condition:
        uint32(0) == 0xe011cfd0 and ($winin and $title)
}
rule INDICATOR_EXE_DotNET_Encrypted {
    meta:
        author = "ditekSHen"
        description = "Detects encrypted or obfuscated .NET executables"
        score = 65
    strings:
        $s1 = "FromBase64String" fullword ascii
        $s2 = "ToCharArray" fullword ascii
        $s3 = "ReadBytes" fullword ascii
        $s4 = "add_AssemblyResolve" fullword ascii
        $s5 = "MemoryStream" fullword ascii
        $s6 = "CreateDecryptor" fullword ascii
        $bytes1 = { 08 01 00 08 00 00 00 00 00 1e 01 00 01 00 54 02
                    16 57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 
                    6e 54 68 72 6f 77 73 01 }
        $bytes2 = { 00 00 42 53 4a 42 01 00 01 00 00 00 00 00 0c 00 
                    00 00 76 3? 2e 3? 2e ?? ?? ?? ?? ?? 00 00 00 00
                    05 00 }
        $bytes3 = { 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 [5] 00 
                    00 00 23 55 53 00 [5] 00 00 00 23 47 55 49 44 00 
                    00 00 [6] 00 00 23 42 6c 6f 62 00 00 00 }
        $bytes4 = { 00 47 65 74 53 74 72 69 6e 67 00 73 65 74 5f 57
                    6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 00
                    57 61 69 74 46 6f 72 45 78 69 74 00 43 6c 6f 73
                    65 00 54 68 72 65 61 64 00 53 79 73 74 65 6d 2e
                    54 68 72 65 61 64 69 6e 67 00 53 6c 65 65 70 00
                    54 6f 49 6e 74 33 32 00 67 65 74 5f 4d 61 69 6e
                    4d 6f 64 75 6c 65 00 50 72 6f 63 65 73 73 4d 6f
                    64 75 6c 65 00 67 65 74 5f 46 69 6c 65 4e 61 6d
                    65 00 53 70 6c 69 74 00 }
    condition:
        uint16(0) == 0x5a4d and 3 of ($bytes*) and all of ($s*)
}
rule INDICATOR_PY_Packed_PyMinifier {
    meta:
        author = "ditekSHen"
        description = "Detects python code potentially obfuscated using PyMinifier"
    strings:
        $s1 = "exec(lzma.decompress(base64.b64decode("
    condition:
        (uint32(0) == 0x6f706d69 or uint16(0) == 0x2123 or uint16(0) == 0x0a0d or uint16(0) == 0x5a4d) and all of them
}
rule INDICATOR_EXE_Packed_Cassandra {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Cassandra/CyaX"
    strings:
        $s1 = "AntiEM" fullword ascii wide
        $s2 = "AntiSB" fullword ascii wide
        $s3 = "Antis" fullword ascii wide
        $s4 = "XOR_DEC" fullword ascii wide
        $s5 = "StartInject" fullword ascii wide
        $s6 = "DetectGawadaka" fullword ascii wide
        $c1 = "CyaX-Sharp" ascii wide
        $c2 = "CyaX_Sharp" ascii wide
        $c3 = "CyaX-PNG" ascii wide
        $c4 = "CyaX_PNG" ascii wide
        $pdb = "\\CyaX\\obj\\Debug\\CyaX.pdb" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s*) or 2 of ($c*) or $pdb)) or (7 of them)
}
rule INDICATOR_EXE_Packed_SilentInstallBuilder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Silent Install Builder"
        snort2_sid = "930070-930072"
        snort3_sid = "930025"
    strings:
        $s1 = "C:\\Users\\Operations\\Source\\Workspaces\\Sib\\Sibl\\Release\\Sibuia.pdb" fullword ascii
        $s2 = "->mb!Silent Install Builder Demo Package." fullword wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_NyanXCat_CSharpLoader {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables utilizing NyanX-CAT C# Loader"
        snort2_sid = "930073-930075"
        snort3_sid = "930026"
    strings:
        $s1 = { 00 50 72 6f 67 72 61 6d 00 4c 6f 61 64 65 72 00 4e 79 61 6e 00 }
    condition:
        uint16(0) == 0x5a4d and all of them
}
rule INDICATOR_EXE_Packed_Loader {
    meta:
        author = "ditekSHen"
        description = "Detects packed executables observed in Molerats"
    strings:
        $l1 = "loaderx86.dll" fullword ascii
        $l2 = "loaderx86" fullword ascii
        $l3 = "loaderx64.dll" fullword ascii
        $l4 = "loaderx64" fullword ascii
        $s1 = "ImportCall_Zw" wide
        $s2 = "DllInstall" ascii wide
        $s3 = "evb*.tmp" fullword wide
        $s4 = "WARNING ZwReadFileInformation" ascii
        $s5 = "LoadLibrary failed with module " fullword wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($l*) and 4 of ($s*)
}
rule INDICATOR_EXE_Packed_Bonsai {
    meta:
         author = "ditekSHen"
        description = "Detects .NET executables developed using Bonsai"
    strings:
        $bonsai1 = "<Bonsai." ascii
        $bonsai2 = "Bonsai.Properties" ascii
        $bonsai3 = "Bonsai.Core.dll" fullword wide
        $bonsai4 = "Bonsai.Design." wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($bonsai*)
}
rule INDICATOR_EXE_Packed_nBinder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with nBinder"
    strings:
        $s4 = "name=\"NKProds.nBinder.Unpacker\" type=\"win" ascii
        $s5 = "<description>nBinder Unpacker. www.nkprods.com</description>" ascii
        $s6 = "nBinder Unpacker (C) NKProds" wide
        $s7 = "\\Proiecte\\nBin" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}
rule INDICATOR_EXE_Packed_AgileDotNet {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Agile.NET / CliSecure"
    strings:
        $x1 = "AgileDotNetRT" fullword ascii
        $x2 = "AgileDotNetRT64" fullword ascii
        $x3 = "<AgileDotNetRT>" fullword ascii
        $x4 = "AgileDotNetRT.dll" fullword ascii
        $x5 = "AgileDotNetRT64.dll" fullword ascii
        $x6 = "get_AgileDotNet" ascii
        $x7 = "useAgileDotNetStackFrames" fullword ascii
        $x8 = "AgileDotNet." ascii
        $x9 = "://secureteam.net/webservices" ascii
        $x10 = "AgileDotNetProtector." ascii
        $s1 = "Callvirt" fullword ascii
        $s2 = "_Initialize64" fullword ascii
        $s3 = "_AtExit64" fullword ascii
        $s4 = "DomainUnload" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*))
}
rule INDICATOR_EXE_Packed_Costura {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Costura DotNetGuard"
    strings:
        $s1 = "DotNetGuard" fullword ascii
        $s2 = "costura." ascii wide
        $s3 = "AssemblyLoader" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
rule INDICATOR_EXE_Packed_SimplePolyEngine {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Sality Polymorphic Code Generator or Simple Poly Engine or Sality"
    strings:
        $s1 = "Simple Poly Engine v" ascii
        $b1 = "yrf<[LordPE]" ascii
        $b2 = "Hello world!" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($b*))
}
rule INDICATOR_EXE_Packed_dotNetProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with dotNetProtector"
    strings:
        $s1 = "dotNetProtector" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
rule INDICATOR_EXE_Packed_DotNetReactor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with unregistered version of .NET Reactor"
    strings:
        $s1 = "is protected by an unregistered version of Eziriz's\".NET Reactor\"!" wide
        $s2 = "is protected by an unregistered version of .NET Reactor!\" );</script>" wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_Dotfuscator {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Dotfuscator"
    strings:
        $s1 = "DotfuscatorAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_DNGuard {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with DNGuard"
    strings:
        $s1 = "DNGuard Runtime library" wide
        $s2 = "[*=*]This application is expired ![*=*]" fullword wide
        $s3 = "DNGuard.Runtime" ascii wide
        $s4 = "EnableHVM" ascii
        $s5 = "DNGuard.SDK" ascii
        $s6 = "DNGuard HVM Runtime" wide
        $s7 = "HVMRuntm.dll" wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}
rule INDICATOR_EXE_Packed_NETProtectIO {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with NETProtect.IO"
    strings:
        $s1 = "NETProtect.IO v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_KoiVM {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with or use KoiVM"
    strings:
        $s1 = "KoiVM v" ascii wide
        $s2 = "DarksVM " ascii wide
        $s3 = "Koi.NG" ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule INDICATOR_EXE_Packed_Babel {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Babel"
    strings:
        $s1 = "BabelObfuscatorAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule upx_0_80_to_1_24 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="UPX 0.80 to 1.24"

	strings:
		$str1={6A 60 68 60 02 4B 00 E8 8B 04 00 00 83 65 FC 00 8D 45 90 50 FF 15 8C F1 48 00 C7 45 FC FE FF FF FF BF 94 00 00 00 57}
		
	condition:
		$str1 at entrypoint
}
rule upx_1_00_to_1_07 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="19/03/2013"
		description="UPX 1.00 to 1.07"

	strings:
		$str1={60 BE 00 ?0 4? 00 8D BE 00 B0 F? FF ?7 8? [3] ?0 9? [0-9] 90 90 90 90 [0-2] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0}
		
	condition:
		$str1 at entrypoint
}
rule upx_3 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="UPX 3.X"

	strings:
		$str1={60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01}
		
	condition:
		$str1 at entrypoint
}
rule obsidium : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="21/01/2013"
		last_edit="17/03/2013"
		description="Obsidium"

	strings:
		$str1={EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04} /*EntryPoint*/
		
	condition:
		$str1 at entrypoint
}
rule pecompact2 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="PECompact"

	strings:
		$str1={B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43} /*EntryPoint*/
		
	condition:
		$str1 at entrypoint
}
rule aspack : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="ASPack"

	strings:
		$str1={60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 ?? ?? 00 00 8D BD B7 3B 40 00 8B F7 AC} /*EntryPoint*/
		
	condition:
		$str1 at entrypoint
}
rule execryptor : Protector
{
	meta:
		author="Kevin Falcoz"
		date_create="25/02/2013"
		description="EXECryptor"

	strings:
		$str1={E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 64 8F 05 00 00 00 00} /*EntryPoint*/
		
	condition:
		$str1 at entrypoint
}
rule winrar_sfx : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="18/03/2013"
		description="Winrar SFX Archive"
	
	strings:
		$signature1={00 00 53 6F 66 74 77 61 72 65 5C 57 69 6E 52 41 52 20 53 46 58 00} 
		
	condition:
		$signature1
}
rule mpress_2_xx_x86 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="19/03/2013"
		last_edit="24/03/2013"
		description="MPRESS v2.XX x86  - no .NET"
	
	strings:
		$signature1={60 E8 00 00 00 00 58 05 5A 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6 2B C0 AC 8B C8 80 E1 F0 24} 
		
	condition:
		$signature1 at entrypoint
}
rule mpress_2_xx_x64 : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="19/03/2013"
		last_edit="24/03/2013"
		description="MPRESS v2.XX x64  - no .NET"
	
	strings:
		$signature1={57 56 53 51 52 41 50 48 8D 05 DE 0A 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31} 
		
	condition:
		$signature1 at entrypoint
}
rule mpress_2_xx_net : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="24/03/2013"
		description="MPRESS v2.XX .NET"
	
	strings:
		$signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}
		
	condition:
		$signature1
}
rule rpx_1_xx : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="24/03/2013"
		description="RPX v1.XX"
	
	strings:
		$signature1= "RPX 1."
		$signature2= "Copyright ©  20"
		
	condition:
		$signature1 and $signature2
}
rule mew_11_xx : Packer
{
	meta:
		author="Kevin Falcoz"
		date_create="25/03/2013"
		description="MEW 11"
	
	strings:
		$signature1={50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
		$signature2="MEW"
		
	condition:
		$signature1 and $signature2
}
