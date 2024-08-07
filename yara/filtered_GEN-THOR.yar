rule APT_Cloaked_PsExec
	{
	meta:
		description = "Looks like a cloaked PsExec. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		id = "e389bb76-0d1d-5e0e-9f79-a3117c919da3"
	strings:
		$s0 = "psexesvc.exe" wide fullword
		$s1 = "Sysinternals PsExec" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1
}
rule APT_Cloaked_CERTUTIL {
   meta:
      description = "Detects a renamed certutil.exe utility that is often used to decode encoded payloads"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-14"
      modified = "2022-06-27"
      id = "13943cda-6bb1-5c6c-8e55-e8d4bba1ffef"
   strings:
      $s1 = "-------- CERT_CHAIN_CONTEXT --------" fullword ascii
      $s5 = "certutil.pdb" fullword ascii
      $s3 = "Password Token" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}
rule SUSP_VULN_DRV_PROCEXP152_May23 {
   meta:
      author = "Florian Roth"
      reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
      date = "2023-05-05"
		modified = "2023-07-28"
      score = 50
      hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
      id = "748eb390-f320-5045-bed2-24ae70471f43"
   strings:
      $a1 = "\\ProcExpDriver.pdb" ascii
      $a2 = "\\Device\\PROCEXP152" wide fullword
      $a3 = "procexp.Sys" wide fullword
   condition:
      uint16(0) == 0x5a4d 
      and all of them
}
rule SUSP_VULN_DRV_PROCEXP152_Renamed_May23 {
   meta:
      author = "Florian Roth"
      reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
      date = "2023-05-05"
      score = 70
      hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
      id = "af2ec5d5-3453-5d35-8d19-4f37c61fabce"
   strings:
      $a1 = "\\ProcExpDriver.pdb" ascii
      $a2 = "\\Device\\PROCEXP152" wide fullword
      $a3 = "procexp.Sys" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and all of them
}
rule SAM_Hive_Backup {
   meta:
      author = "Florian Roth"
      reference = "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-hashes-from-sam-registry"
      score = 60
      nodeepdive = 1
      date = "2015-03-31"
      modified = "2023-12-12"
      id = "31fb6c0c-966d-5002-bf8c-4129964c81ff"
   strings:
      $s1 = "\\SystemRoot\\System32\\Config\\SAM" wide
   condition:
      uint32(0) == 0x66676572 and $s1 in (0..200)
}
