rule ConfuserEx_Watermark {
	meta:
		description = "Detects ConfuserEx watermark in .NET binaries. Most of the time this is removed, but here for completeness"
	strings:
		$s1 = "ConfuserEx v"
		$s2 = "Confuser.Core"
		$s3 = "ConfusedByAttribute"
	condition:
		$s1 or $s2 or $s3
}
rule SuppressIldasm {
	meta:
		description = "Detects SuppressIldasm attribute in .NET binaries, not specific to ConfuserEx"
	strings:
		$s1 = "SuppressIldasmAttribute"
	condition:
		$s1
}
rule ConfuserEx_Constants {
	meta:
		description = "ConfuserEx constants protection which may include string protection, primitives, etc."
	strings:
		$s1 = "CreateInstance"
		$s2 = "GetElementType"
		$s3 = "BlockCopy"
		$s4 = "GetString"
		$shift = { 11 08 11 06 }
	condition:
		$s1 and $s2 and $s3 and $s4 and $shift 
}
rule ConfuserEx_ControlFlow_Switch {
	strings:
		$switch = { 20 [4] 61 25 0A ?? 5E 45 }
	condition:
		$switch
}
rule ConfuserEx_AntiDebug_Win32 {
	meta:
		description = "ConfuserEx anti-debugging protection in \"win32\" mode"
	strings:
		$s1 = "CloseHandle"
		$s2 = "IsDebuggerPresent"
		$s3 = "OutputDebugString"
		$s4 = "ParameterizedThreadStart"
	condition:
		$s1 and $s2 and $s3 and $s4
}
rule ConfuserEx_AntiDebug_Antinet {
	meta:
		description = "ConfuserEx anti-debugging protection in \"antinet\" mode"
	strings:
		$s1 = "kernel32"
		$s2 = "GetCurrentProcessId"
		$s3 = "CreateNamedPipe"
		$s4 = "CreateFile"
	condition:
		$s1 and $s2 and $s3 and $s4
}
rule ConfuserEx_InvalidMetadata {
	strings:
		$s1 = "#Strings"
		$s2 = "#GUID"
		$s3 = "#Blob"
		$h1 = { FF 7F FF 7F FF 7F }
	condition:
		#s1 > 1
		and #s2 > 1
		and #s3 > 1
		and $h1
}
rule ConfuserEx_RefProxy_Strong {
	strings:
		$s1 = "GetFieldFromHandle"
		$s2 = "ResolveSignature"
		$s3 = "GetOptionalCustomModifiers"
		$s4 = "SetLocalSignature"
	condition:
		$s1
		and $s2
		and $s3
		and $s4
}
rule ConfuserEx_Resources_Protection {
	strings:
		$s1 = "get_CurrentDomain"
		$s2 = "add_AssemblyResolve"
	condition:
		$s1
		and $s2
}
rule ConfuserEx_Packer {
	meta:
		description = "ConfuserEx packer/compressor mode"
	strings:
		$s1 = "GCHandle"
		$s2 = "Free"
		$s3 = "GetExecutingAssembly"
		$s4 = "GetEntryAssembly"
		$s5 = "GetManifestResourceStream"
		$s6 = "LoadModule"
	condition:
		$s1
		and $s2
		and $s3
		and $s4
		and $s5
		and $s6
}