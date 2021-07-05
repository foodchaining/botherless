::
:: Botherless Security Script
:: https://github.com/foodchaining/botherless
::
:: Copyright: (C) 2021 foodchaining
:: License: GNU GPL v3 or later
::
::
@ECHO OFF & SETLOCAL & SET BOTHERLESS_FILE=%~f0 & SET BOTHERLESS_ARGS=%*
PowerShell -Command "& {" ^
	"$C = Get-Content -Path '%BOTHERLESS_FILE%' -Raw -Encoding 'UTF8'; " ^
	"$X = $C.Substring($C.LastIndexOf('P2kjEpbW5A') + 10); " ^
	"Invoke-Expression -Command $X}" & EXIT
:: P2kjEpbW5A

$ErrorActionPreference = "Stop"
Set-StrictMode -Version "3.0"

$BLVersion = "0.1.0"

$VOID = New-Object -TypeName "PSObject"

$ERRGET = New-Object -TypeName "PSObject"
$ERRSET = New-Object -TypeName "PSObject"

$script:BLFlags = $null
$script:DGStatus = $null
$script:AMStatus = $null

function ArgCreateCheckpoint {
	return $BLFlags -icontains "-CreateCheckpoint"
}

function ArgTackle {
	return $BLFlags -icontains "-Tackle"
}

function ArgNoIntroWarning {
	return $BLFlags -icontains "-NoIntroWarning"
}

function ArgAllowRestrictedUserMode {
	return $BLFlags -icontains "-AllowRestrictedUserMode"
}

function ArgForceRelocateImages {
	return $BLFlags -icontains "-ForceRelocateImages"
}

function GetDesiredForceRelocateImages {
	if (ArgForceRelocateImages)
		{ return "ON" }
	else
		{ return "OFF" }
}

function ArgNoAutoRebootWithLoggedOnUsers {
	return $BLFlags -icontains "-NoAutoRebootWithLoggedOnUsers"
}

function ArgAuditPrevalenceAgeOrTrustedListCriterion {
	return $BLFlags -icontains "-AuditPrevalenceAgeOrTrustedListCriterion"
}

function GetDesiredPrevalenceAgeOrTrustedListCriterion {
	if (ArgAuditPrevalenceAgeOrTrustedListCriterion)
		{ return 2 }
	else
		{ return 0 }
}

function GetDesiredPrevalenceAgeOrTrustedListCriterionDescription {
	if (ArgAuditPrevalenceAgeOrTrustedListCriterion)
		{ return ("Audit executable files upon running unless they " +
			"meet a prevalence, age, or trusted list criterion") }
	else
		{ return ("Allow executable files to run regardless of whether they " +
			"meet a prevalence, age, or trusted list criterion") }
}

function ArgHighPlusBlockingLevel {
	return $BLFlags -icontains "-HighPlusBlockingLevel"
}

function GetDesiredBlockingLevel {
	if (ArgHighPlusBlockingLevel)
		{ return 4 }
	else
		{ return 2 }
}

function ArrayToSet($list) {
	$set = @{}
	foreach ($e in $list)
		{ $set[$e] = $true }
	return $set
}

function CommaStrToSet($str) {
	return ArrayToSet @($str -split "," | % {$_.Trim()} | ? {$_})
}

function SetToCommaStr($set) {
	return @($set.Keys | % {$_.Trim()} | ? {$_}) -join ","
}

function DeepEqual($a0, $a1, [scriptblock]$equality) {

	if (($null -eq $a0) -and ($null -eq $a1))
		{ return $true }
	if (($null -eq $a0) -or ($null -eq $a1))
		{ return $false }

	if (($a0 -is [valuetype]) -and ($a1 -is [valuetype]))
		{ return (& $equality $a0 $a1) -and (& $equality $a1 $a0) }
	if (($a0 -is [valuetype]) -or ($a1 -is [valuetype]))
		{ return $false }

	if (($a0 -is [array]) -and ($a1 -is [array])) {
		if ($a0.Equals($a1))
			{ return $true }
		if ($a0.Length -ne $a1.Length)
			{ return $false }
		for ($i = 0; $i -lt $a0.Length; ++$i) {
			if (!(DeepEqual $a0[$i] $a1[$i] $equality))
				{ return $false }
		}
		return $true
	}
	if (($a0 -is [array]) -or ($a1 -is [array]))
		{ return $false }

	if (($a0 -is [hashtable]) -and ($a1 -is [hashtable])) {
		if ($a0.Equals($a1))
			{ return $true }
		if ($a0.Count -ne $a1.Count)
			{ return $false }
		foreach ($it in $a0.GetEnumerator()) {
			if (!($a1.ContainsKey($it.Key)))
				{ return $false }
			if (!(DeepEqual $it.Value $a1[$it.Key] $equality))
				{ return $false }
		}
		return $true
	}
	if (($a0 -is [hashtable]) -or ($a1 -is [hashtable]))
		{ return $false }

	if ($a0.GetType() -eq $a1.GetType())
		{ return (& $equality $a0 $a1) -and (& $equality $a1 $a0) }
	else
		{ return $false }
}

function Equal($a0, $a1) {
	function equality($a0, $a1) { return $a0 -eq $a1 }
	return DeepEqual $a0 $a1 ${function:equality}
}

function EqualI($a0, $a1) {
	function equality($a0, $a1) { return $a0 -ieq $a1 }
	return DeepEqual $a0 $a1 ${function:equality}
}

function EqualC($a0, $a1) {
	function equality($a0, $a1) { return $a0 -ceq $a1 }
	return DeepEqual $a0 $a1 ${function:equality}
}

function EQ($a0, $a1) { return Equal $a0 $a1 }
function NE($a0, $a1) { return !(Equal $a0 $a1) }

function IEQ($a0, $a1) { return EqualI $a0 $a1 }
function CEQ($a0, $a1) { return EqualC $a0 $a1 }

function GetKind($value) {
	if ($null -eq $value)
		{ return $null }
	else
		{ return $value.GetType() }
}

function EqualKinds($a0, $a1) {
	return (GetKind $a0) -eq (GetKind $a1)
}

function Pick {
	$index = [int]($args[0])
	return $args[1 + $index]
}

function GetElement {
	$current = $args[0]
	for ($i = 1; $i -lt $args.Length; ++$i) {
		if ($null -ne $current)
			{ $current = $current[$args[$i]] }
		else
			{ break }
	}
	return $current
}

function DumpVersion {
	Write-Host "Botherless Security Script Version" $BLVersion
}

function ConfirmWarning {
	DumpVersion
	try {
		Write-Warning -WarningAction "Inquire" (
			"This script can enable certain Windows built-in boot-critical " +
			"security options (WDAC, VBS, HVCI, ELAM, DEP, DSE, etc) which " +
			"in rare cases may render the system unbootable. " +
			"Proceed only if a System Restore Point was recently created! " +
			"(See '-CreateCheckpoint' switch parameter.)")
	} catch
		[System.Management.Automation.ParentContainsErrorRecordException]
		{ exit 1 }
}

function DumpReport($code, $info, $indent = 0) {
	for ($i = 0; $i -lt $indent; ++$i)
		{ Write-Host " " -NoNewline }
	Write-Host "[" -NoNewline
	switch ($code) {
		0 { Write-Host "+" -NoNewline}
		1 { Write-Host "+" -NoNewline -ForegroundColor Green }
		2 { Write-Host "X" -NoNewline -ForegroundColor Red }
		3 { Write-Host "R" -NoNewline -ForegroundColor Red }
		4 { Write-Host "W" -NoNewline -ForegroundColor Red }
		default { Write-Host "?" -NoNewline -ForegroundColor Yellow `
			-BackgroundColor Magenta }
	}
	Write-Host "] $info"
}

function ReportToInt($report) {
	if (EQ $VOID $report)
		{ return 0 }
	if (EQ $true $report)
		{ return 1 }
	if (EQ $false $report)
		{ return 2 }
	if (EQ $ERRGET $report)
		{ return 3 }
	if (EQ $ERRSET $report)
		{ return 4 }
	return 5
}

function PCCheck($report) {
	if (EQ $true $report)
		{ return $VOID }
	if (EQ $false $report)
		{ return $false }
	return $ERRGET
}

function CompoundReport($report, $dv, $gv, $uv, [scriptblock]$eq) {
	if ($null -eq $uv)
		{ return Pick (& $eq $dv $gv) $report $VOID }
	else {
		if (& $eq $dv $uv)
			{ return Pick (& $eq $dv $gv) $true $VOID }
		else
			{ return $report }
	}
}

function Report($report, $info) {
	DumpReport -code (ReportToInt $report) -info $info
}

function ReportMulti($info, $reports) {
	if (!($reports -is [array])) {
		Report $reports $info
		return
	}
	$root = 0
	foreach ($report in $reports) {
		$code = ReportToInt $report[0]
		if ($code -gt $root)
			{ $root = $code }
	}
	DumpReport -code $root -info $info
	if ($root -gt 0) {
		foreach ($report in $reports) {
			$code = ReportToInt $report[0]
			DumpReport -code $code -info $report[1] -indent 2
		}
	}
}

function HasSecureBoot {
	return $DGStatus.AvailableSecurityProperties -contains 2
}

function HasDMAProtection {
	return $DGStatus.AvailableSecurityProperties -contains 3
}

function HasSecureBootWithDMA {
	return (HasSecureBoot) -and (HasDMAProtection)
}

function HasHypervisor {
	return $DGStatus.AvailableSecurityProperties -contains 1
}

function HasMBEC {
	return $DGStatus.AvailableSecurityProperties -contains 7
}

function HasHVCI {
	return (HasHypervisor) -and ((HasMBEC) -or (ArgAllowRestrictedUserMode))
}

function ConfirmSecureBoot {
	try {
		return EQ (Confirm-SecureBootUEFI) $true
	} catch
		[System.UnauthorizedAccessException]
		{ }
	return $VOID
}

function ConfirmConstrainedMode {
	$langmode = PowerShell -Command ("& { @( " +
		"`$Host.Runspace.LanguageMode, " +
		"`$ExecutionContext.SessionState.LanguageMode " +
	") }")
	return ($langmode -is [array]) -and ($langmode.Length -eq 2) `
		-and ("ConstrainedLanguage" -ieq $langmode[0]) `
		-and ("ConstrainedLanguage" -ieq $langmode[1])
}

function GetBinaryContent($path) {
	return Get-Content -Path $path -Raw -Encoding "Byte"
}

function SetBinaryContent($path, $value) {
	Set-Content -Path $path -Force -Value $value -Encoding "Byte"
}

function ReadIniFile($path) {
	$lines = Get-Content -Path $path
	$ini = @{}
	$section = $null
	switch -Regex ($lines)
	{
		'^\s*(.+?)\s*=(.*)$'
		{
			if ($null -eq $section)
				{ return $null }
			$name, $value = $Matches[1..2]
			$ini[$section][$name] = $value
			continue
		}
		'^\s*\[(.+)\]\s*$'
		{
			$section = $Matches[1]
			if (!($ini.ContainsKey($section)))
				{ $ini[$section] = @{} }
			continue
		}
		'^\s*;.*$'
			{ continue }
		default
			{ return $null }
	}
	return $ini
}

function WriteIniFile($ini, $path) {
	$content = @()
	foreach ($i in $ini.Keys | sort) {
		$content += "[$i]"
		foreach ($j in $ini[$i].Keys | sort)
			{ $content += "$j=$($ini[$i][$j])" }
	}
	Set-Content -Path $path -Value $content
}

function GenerateBaseWDACPolicy {
	$base = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml"
	$temp = (New-TemporaryFile).FullName
	$null = ConvertFrom-CIPolicy -XmlFilePath $base -BinaryFilePath $temp
	return GetBinaryContent -path $temp
}

function GetBaseWDACPolicy {
	# This is the result of 'GenerateBaseWDACPolicy' function calling
	# (on Windows 10 Pro, Build 19043.1052)
	[byte[]]@(7,0,0,0,14,55,68,162,201,68,6,76,181,81,246,1,110,86,48,118,228,
	247,7,46,76,25,32,77,183,201,111,68,166,197,162,52,4,0,136,144,0,0,0,0,2,0,
	0,0,0,0,0,0,2,0,0,0,0,0,1,0,0,0,1,0,64,0,0,0,1,0,0,0,2,0,0,0,42,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,2,0,0,0,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,131,0,0,0,0,0,0,0,12,128,0,0,0,0,0,0,0,0,0,0,1,0,0,
	0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,0,0,0,0,0,0,0,
	12,128,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,20,0,0,0,80,0,111,0,108,0,105,0,99,0,121,0,
	73,0,110,0,102,0,111,0,0,0,0,0,22,0,0,0,73,0,110,0,102,0,111,0,114,0,109,0,
	97,0,116,0,105,0,111,0,110,0,0,0,0,0,0,0,4,0,0,0,73,0,100,0,0,0,0,0,3,0,0,0,
	12,0,0,0,48,0,52,0,49,0,52,0,49,0,55,0,0,0,0,0,20,0,0,0,80,0,111,0,108,0,
	105,0,99,0,121,0,73,0,110,0,102,0,111,0,0,0,0,0,22,0,0,0,73,0,110,0,102,0,
	111,0,114,0,109,0,97,0,116,0,105,0,111,0,110,0,0,0,0,0,0,0,8,0,0,0,78,0,97,
	0,109,0,101,0,0,0,0,0,3,0,0,0,16,0,0,0,65,0,108,0,108,0,111,0,119,0,65,0,
	108,0,108,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,6,0,0,0,14,55,68,162,201,68,6,76,181,81,246,1,110,
	86,48,118,14,55,68,162,201,68,6,76,181,81,246,1,110,86,48,118,0,0,0,0,7,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0)
}

function FetchDGStatus {
	$script:DGStatus = Get-CimInstance -ClassName "Win32_DeviceGuard" `
		-Namespace "root\Microsoft\Windows\DeviceGuard"
}

function GetDefaultAdministrator {
	return Get-CimInstance -ClassName "Win32_UserAccount" `
		-Filter "LocalAccount = 'True' AND SID LIKE 'S-1-5-%-500'"
}

function ConfigureRegistry($item, $property, $type, $value) {

	function getter {
		try {
			$got = (Get-ItemProperty -Path $item -Name $property).$property
		} catch
			[System.Management.Automation.ItemNotFoundException],
			[System.Management.Automation.PSArgumentException]
			{ $got = $VOID }
		return $got
	}

	$got = getter

	if ((CEQ $got $value) -and (EqualKinds $got $value))
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	try {
		if (NE $value $VOID) {
			if (!(Test-Path $item))
				{ $null = New-Item $item -Force }
			Set-ItemProperty -Path $item -Name $property `
				-Type $type -Value $value
		} else
			{ Remove-ItemProperty -Path $item -Name $property }
	} catch
		[System.Security.SecurityException],
		[System.UnauthorizedAccessException]
		{ return $ERRSET }

	$got = getter

	return (CEQ $got $value) -and (EqualKinds $got $value)
}

function ConfigureSecurityPolicy($conf) {

	$desired = @{}
	foreach ($i in $conf.GetEnumerator()) {
		$desired[$i.Key] = @{}
		foreach ($j in $i.Value.GetEnumerator())
			{ $desired[$i.Key][$j.Key] = $j.Value[0] }
	}

	$secedit = "$env:windir\System32\SecEdit.exe"

	function getter {
		$temp = (New-TemporaryFile).FullName

		& $secedit "/export" "/areas" "SECURITYPOLICY" "USER_RIGHTS" `
			"/cfg" $temp > $null
		if (! $?)
			{ return $ERRGET }

		$complete = ReadIniFile -path $temp
		if ($null -eq $complete)
			{ return $ERRGET }

		$relevant = @{}
		foreach ($i in $conf.GetEnumerator()) {
			$relevant[$i.Key] = @{}
			foreach ($j in $i.Value.GetEnumerator()) {
				if ($complete.ContainsKey($i.Key) `
					-and $complete[$i.Key].ContainsKey($j.Key))
				{
					$relevant[$i.Key][$j.Key] =
						& ($j.Value[1]) $complete[$i.Key][$j.Key]
				} else
					{ $relevant[$i.Key][$j.Key] = & ($j.Value[1]) "" }
			}
		}
		return $relevant
	}

	function report($report, $got, $updated) {
		$reports = @()
		foreach ($i in $conf.GetEnumerator()) {
			foreach ($j in $i.Value.GetEnumerator()) {
				$dv = $j.Value[0]
				$gv = $got[$i.Key][$j.Key]
				$uv = GetElement $updated $i.Key $j.Key
				$cr = CompoundReport $report $dv $gv $uv ${function:CEQ}
				$reports += @(, @($cr, $j.Value[3], $j.Value[4]))
			}
		}
		return $reports | sort @{e = {$_[2]}}
	}

	$got = getter

	if (EQ $got $ERRGET)
		{ return $ERRGET }
	elseif (CEQ $got $desired)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return report $false $got $null }

	$ini = @{}
	foreach ($i in $conf.GetEnumerator()) {
		$ini[$i.Key] = @{}
		foreach ($j in $i.Value.GetEnumerator())
			{ $ini[$i.Key][$j.Key] = & ($j.Value[2]) $j.Value[0] }
	}
	$ini["Unicode"] = @{"Unicode" = "yes"}
	$ini["Version"] = @{"Signature" = "`"`$CHICAGO`$`""; "Revision" = "1"}
	$tempIni = (New-TemporaryFile).FullName
	$tempSdb = (New-TemporaryFile).FullName + "." +
		(Get-Random -Minimum 100 -Maximum 1000)
	WriteIniFile -ini $ini -path $tempIni

	& $secedit "/configure" "/areas" "SECURITYPOLICY" "USER_RIGHTS" `
		"/cfg" $tempIni "/db" $tempSdb "/quiet" > $null
	if (! $?)
		{ return report $ERRSET $got (getter) }

	return report $false $got (getter)
}

function ConfigureMpPreference($preference, $value) {

	function getter {
		$got = Get-MpPreference | Select-Object -ExpandProperty $preference
		return $got
	}

	$got = getter

	if (CEQ $got $value)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	try {
		$parameters = @{ $preference = $value }
		Set-MpPreference -ErrorAction "Stop" @parameters
	} catch
		[Microsoft.Management.Infrastructure.CimException]
		{ return $ERRSET }

	$got = getter

	return CEQ $got $value
}

function ConfigureASRRules($rules) {

	$desired = @{}
	foreach ($i in $rules.GetEnumerator())
		{ $desired[$i.Key] = $i.Value[0] }

	function getter {
		$prefs = Get-MpPreference
		$ids = $prefs.AttackSurfaceReductionRules_Ids
		$actions = $prefs.AttackSurfaceReductionRules_Actions
		$isarray = ($ids -is [array]) -and ($actions -is [array])
		$got = @{}
		if ($isarray -and ($ids.Length -eq $actions.Length)) {
			for ($i = 0; $i -lt $ids.Length; ++$i)
				{ $got[$ids[$i]] = $actions[$i] }
		}
		return $got
	}

	function report($report, $got, $updated) {
		$reports = @()
		foreach ($i in $rules.GetEnumerator()) {
			$dv = $i.Value[0]
			$gv = $got[$i.Key]
			$uv = GetElement $updated $i.Key
			$cr = CompoundReport $report $dv $gv $uv ${function:EQ}
			$reports += @(, @($cr, $i.Value[1], $i.Value[2]))
		}
		return $reports | sort @{e = {$_[2]}}
	}

	$got = getter
	foreach ($i in $got.GetEnumerator()) {
		if (! $desired.ContainsKey($i.Key))
			{ $desired[$i.Key] = $i.Value }
	}

	if (EQ $got $desired)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return report $false $got $null }

	try {
		Set-MpPreference -ErrorAction "Stop" `
			-AttackSurfaceReductionRules_Ids $desired.Keys `
			-AttackSurfaceReductionRules_Actions $desired.Values
	} catch
		[Microsoft.Management.Infrastructure.CimException]
		{ return report $ERRSET $got (getter) }

	return report $false $got (getter)
}

function ConfigureExploitMitigations($info) {

	$base = @{
		"DEP.Enable" = "ON"
		"DEP.EmulateAtlThunks" = "OFF"
		"ASLR.ForceRelocateImages" = GetDesiredForceRelocateImages
		"ASLR.RequireInfo" = "OFF"
		"ASLR.BottomUp" = "ON"
		"ASLR.HighEntropy" = "ON"
		"CFG.Enable" = "ON"
		"CFG.SuppressExports" = "OFF"
		#"CFG.StrictControlFlowGuard" = "OFF"
		"SEHOP.Enable" = "ON"
		"SEHOP.TelemetryOnly" = "OFF"
		"Heap.TerminateOnError" = "ON"
	}

	function getter {
		$obj = Get-ProcessMitigation -System
		return @{
			"DEP.Enable" = [string]$obj.DEP.Enable
			"DEP.EmulateAtlThunks" = [string]$obj.DEP.EmulateAtlThunks
			"ASLR.ForceRelocateImages" = [string]$obj.ASLR.ForceRelocateImages
			"ASLR.RequireInfo" = [string]$obj.ASLR.RequireInfo
			"ASLR.BottomUp" = [string]$obj.ASLR.BottomUp
			"ASLR.HighEntropy" = [string]$obj.ASLR.HighEntropy
			"CFG.Enable" = [string]$obj.CFG.Enable
			"CFG.SuppressExports" = [string]$obj.CFG.SuppressExports
			#"CFG.StrictControlFlowGuard" =
			#	[string]$obj.CFG.StrictControlFlowGuard
			"SEHOP.Enable" = [string]$obj.SEHOP.Enable
			"SEHOP.TelemetryOnly" = [string]$obj.SEHOP.TelemetryOnly
			"Heap.TerminateOnError" = [string]$obj.Heap.TerminateOnError
		}
	}

	$got = getter

	if (IEQ $got $base)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	$E = @()
	$D = @()
	if ($base["DEP.Enable"] -ine "OFF")
		{ $E += "DEP" } else { $D += "DEP" }
	if ($base["DEP.EmulateAtlThunks"] -ine "OFF")
		{ $E += "EmulateAtlThunks" } else { $D += "EmulateAtlThunks" }
	if ($base["ASLR.ForceRelocateImages"] -ine "OFF")
		{ $E += "ForceRelocateImages" } else { $D += "ForceRelocateImages" }
	if ($base["ASLR.RequireInfo"] -ine "OFF")
		{ $E += "RequireInfo" } else { $D += "RequireInfo" }
	if ($base["ASLR.BottomUp"] -ine "OFF")
		{ $E += "BottomUp" } else { $D += "BottomUp" }
	if ($base["ASLR.HighEntropy"] -ine "OFF")
		{ $E += "HighEntropy" } else { $D += "HighEntropy" }
	if ($base["CFG.Enable"] -ine "OFF")
		{ $E += "CFG" } else { $D += "CFG" }
	if ($base["CFG.SuppressExports"] -ine "OFF")
		{ $E += "SuppressExports" } else { $D += "SuppressExports" }
	#if ($base["CFG.StrictControlFlowGuard"] -ine "OFF")
	#	{ $E += "StrictCFG" } else { $D += "StrictCFG" }
	if ($base["SEHOP.Enable"] -ine "OFF")
		{ $E += "SEHOP" } else { $D += "SEHOP" }
	if ($base["SEHOP.TelemetryOnly"] -ine "OFF")
		{ $E += "SEHOPTelemetry" } else { $D += "SEHOPTelemetry" }
	if ($base["Heap.TerminateOnError"] -ine "OFF")
		{ $E += "TerminateOnError" } else { $D += "TerminateOnError" }
	$parameters = @{ "Force" = "off" }
	if ($E.Length -ne 0)
		{ $parameters["Enable"] = $E }
	if ($D.Length -ne 0)
		{ $parameters["Disable"] = $D }
	try {
		Set-ProcessMitigation -System -WarningAction "Stop" @parameters *> $null
	} catch
		[System.Management.Automation.ParentContainsErrorRecordException]
		{ return $ERRSET }

	$got = getter

	return IEQ $got $base
}

function ConfigureBootOption($option, $value) {

	$bcdedit = "$env:windir\System32\bcdedit.exe"

	function getter {
		$pattern = '^' + [regex]::escape($option) + '\s+(\w+)$'
		$out = & $bcdedit "/enum" "{current}"
		if (! $?)
			{ return $ERRGET }
		$info = $out | Select-String -Pattern $pattern
		if (($null -ne $info) -and ($info.Matches.Length -eq 1))
			{ return $info.Matches[0].Groups[1].Value }
		return $VOID
	}

	$got = getter

	if (EQ $got $ERRGET)
		{ return $ERRGET }
	elseif (IEQ $got $value)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	& $bcdedit "/set" "{current}" $option $value > $null
	if (! $?)
		{ return $ERRSET }

	$got = getter

	return IEQ $got $value
}

function ConfigurePowerShellPolicy($value) {

	function getter {
		$got = [string](Get-ExecutionPolicy -Scope "LocalMachine")
		return $got
	}

	$got = getter

	if (IEQ $got $value)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	try {
		Set-ExecutionPolicy -ExecutionPolicy $value -Scope "LocalMachine" -Force
	} catch
		[System.UnauthorizedAccessException]
		{ return $ERRSET }

	$got = getter

	return IEQ $got $value
}

function ConfigureService($name, $startup, $state) {

	$conf = @{"startup" = $startup; "state" = $state }

	function getter {
		$service = Get-Service -Name $name
		$got = @{ "startup" = [string]$service.StartType }
		if ($null -eq $state)
			{ $got["state"] = $null }
		else
			{ $got["state"] = [string]$service.Status }
		return $got
	}

	$got = getter

	if (IEQ $got $conf)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	try {
		if ($null -eq $state)
			{ Set-Service -Name $name -StartupType $startup }
		else
			{ Set-Service -Name $name -StartupType $startup -Status $state }
	} catch
		[Microsoft.PowerShell.Commands.ServiceCommandException]
		{ return $ERRSET }

	$got = getter

	return IEQ $got $conf
}

function ConfigureWDAC() {

	$wdac = "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"
	$multi = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
	$policy = GetBaseWDACPolicy
	$desired = @{ "policy" = $policy; "running" = $true }

	function getter {
		try {
			$running =
				(EQ $DGStatus.CodeIntegrityPolicyEnforcementStatus 2) -and `
				(EQ $DGStatus.UsermodeCodeIntegrityPolicyEnforcementStatus 2)
			try {
				if (@(Get-ChildItem -Path $multi).Count -ne 0)
					{ return @{ "policy" = $VOID; "running" = $running } }
			} catch
				[System.Management.Automation.ItemNotFoundException]
				{ }
			try {
				return @{ "policy" = (GetBinaryContent -path $wdac)
					"running" = $running }
			} catch
				[System.Management.Automation.ItemNotFoundException]
				{ return @{ "policy" = $VOID; "running" = $running } }
		} catch
			[System.UnauthorizedAccessException]
			{ return $ERRGET }
	}

	function report($report, $got, $updated) {
		$rWrite = CompoundReport $report $policy $got["policy"] `
			(GetElement $updated "policy") ${function:EQ}
		$rStart = CompoundReport $report $true $got["running"] `
			(GetElement $updated "running") ${function:EQ}
		return @(
			@($rWrite, "Install WDAC policy binary file"),
			@($rStart, "Start WDAC or update its policy without reboot")
		)
	}

	$got = getter

	if (EQ $got $ERRGET)
		{ return $ERRGET }
	elseif (EQ $got $desired)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return report $false $got $null }

	try {
		Remove-Item -Path "$multi\*" -Force -Recurse
		SetBinaryContent -path $wdac -value $policy
		$rval = Invoke-CimMethod -Namespace "root\Microsoft\Windows\CI" `
			-ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" `
			-Arguments @{ "FilePath" = $wdac }
		if (0 -ne $rval.ReturnValue)
			{ return report $ERRSET $got (getter) }
	} catch
		[System.Management.Automation.ItemNotFoundException],
		[System.UnauthorizedAccessException],
		[Microsoft.Management.Infrastructure.CimException]
		{ return report $ERRSET $got (getter) }

	FetchDGStatus

	return report $false $got (getter)
}

function ConfigureOptionalFeature($feature, $value) {

	function getter {
		try {
			$obj = Get-WindowsOptionalFeature -Online -FeatureName $feature
			if ($null -ne $obj) {
				$state = [string]$obj.State
				if ($state -ieq "Disabled")
					{ return $false }
				elseif ($state -ieq "Enabled")
					{ return $true }
			}
		} catch
			[System.Runtime.InteropServices.COMException]
			{ }
		return $ERRGET
	}

	$got = getter

	if (EQ $got $ERRGET)
		{ return $ERRGET }
	elseif (EQ $got $value)
		{ return $VOID }
	elseif (!(ArgTackle))
		{ return $false }

	try {
		$parameters = @{"Online" = $true; "FeatureName" = $feature
			"NoRestart" = $true; "WarningAction" = "SilentlyContinue"}
		if ($value)
			{ $null = Enable-WindowsOptionalFeature @parameters }
		else
			{ $null = Disable-WindowsOptionalFeature @parameters }
	} catch
		[System.Runtime.InteropServices.COMException]
		{ return $ERRSET }

	$got = getter

	return EQ $got $value
}

function ConfigureAll {

	$allFlags = @{
		"-CreateCheckpoint" = ""
		"-Tackle" = ""
		"-NoIntroWarning" = ""
		"-AllowRestrictedUserMode" = ""
		"-ForceRelocateImages" = ""
		"-NoAutoRebootWithLoggedOnUsers" = ""
		"-AuditPrevalenceAgeOrTrustedListCriterion" = ""
		"-HighPlusBlockingLevel" = ""
	}

	$local:BLFlags = @($env:BOTHERLESS_ARGS -split " " | % {$_.Trim()} | ? {$_})

	foreach ($flag in $BLFlags) {
		if (!$allFlags.ContainsKey($flag)) {
			Write-Host "Bad parameter $flag"
			exit 1
		}
	}

	$osInfo = Get-CimInstance -ClassName "Win32_OperatingSystem"

	if (([int]$osInfo.BuildNumber -lt 19041) -or ([intptr]::Size -lt 8)) {
		Write-Host "At least 20H1 version of 64-bit Windows is required"
		exit 1
	}

	if (ArgCreateCheckpoint) {
		if ($BLFlags.Length -ne 1) {
			Write-Host "Bad parameters"
			exit 1
		}
		try {
			Enable-ComputerRestore -Drive $osInfo.SystemDrive
			Checkpoint-Computer -Description "Botherless Checkpoint" `
				-RestorePointType "MODIFY_SETTINGS" -WarningAction "Stop"
			@((Get-ComputerRestorePoint))[-1]
			exit 0
		}
		catch
			[System.Management.ManagementException]
		{
			$msg = ([string]$_).Trim()
			Write-Warning "A System Restore Point was not created. ($msg)"
		}
		catch
			[System.Management.Automation.ParentContainsErrorRecordException]
			{ }
		exit 1
	}

	if ((ArgTackle) -and !(ArgNoIntroWarning))
		{ ConfirmWarning }

	FetchDGStatus

	ReportMulti "Configure and run Windows Defender Application Control" `
		(ConfigureWDAC)

	Report (ConfigureBootOption -option "nx" -value "AlwaysOn") `
		"Enable DEP for the operating system and all processes"

	if (!(HasSecureBoot)) {
		Report (ConfigureBootOption -option "nointegritychecks" -value "No") `
			"Enable Driver Signature Enforcement"
	}

	if (HasHypervisor) {
		$reports = @(
			@((ConfigureBootOption -option "hypervisorlaunchtype" `
				-value "Auto"), "Enable VBS boot option"),
			@((ConfigureRegistry -item `
				"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
				-property "EnableVirtualizationBasedSecurity" `
				-type "DWord" -value 1), "Enable VBS registry option")
		)
		if (HasSecureBootWithDMA) {
			$reports += @(, @((ConfigureRegistry -item `
				"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
				-property "RequirePlatformSecurityFeatures" `
				-type "DWord" -value 1), "Require Secure Boot with DMA"))
		} elseif (HasSecureBoot) {
			$reports += @(, @((ConfigureRegistry -item `
				"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
				-property "RequirePlatformSecurityFeatures" `
				-type "DWord" -value 3), "Require Secure Boot"))
		}
		ReportMulti "Enable Virtualization Based Security" $reports
	}

	if (HasHVCI) {
		Report (ConfigureRegistry -item (
			"HKLM:\SYSTEM\CurrentControlSet\Control\" +
				"DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity") `
			-property "Enabled" -type "DWord" -value 1) `
			"Enable hypervisor-assisted protection of Code Integrity policies"
	}

	ReportMulti "Disable deprecated Windows components" @(
		@((ConfigureOptionalFeature -feature "SMB1Protocol" -value $false),
			"Disable SMB 1.0/CIFS File Sharing Support"),
		@((ConfigureOptionalFeature `
			-feature "MicrosoftWindowsPowerShellV2Root" -value $false),
			"Disable Windows PowerShell 2.0")
	)

	ReportMulti "Restrict Windows scripting environment" @(
		@((ConfigurePowerShellPolicy -value "Restricted"),
			"(1/3) Restrict PowerShell execution policy"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
			-property "ExecutionPolicy" -type "String" -value "Restricted"),
			"(2/3) Restrict PowerShell execution policy"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
			-property "EnableScripts" -type "DWord" -value 0),
			"(3/3) Restrict PowerShell execution policy"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
			-property "Enabled" -type "DWord" -value 0),
			"(1/2) Disable Windows Script Host"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\" +
				"WOW6432Node\Microsoft\Windows Script Host\Settings") `
			-property "Enabled" -type "DWord" -value 0),
			"(2/2) Disable Windows Script Host")
	)

	Report (ConfigureRegistry -item ("HKLM:\SYSTEM\CurrentControlSet\" +
			"Control\Session Manager\Environment") `
		-property "MP_FORCE_USE_SANDBOX" -type "String" -value "1") `
		"Run Windows Defender in a sandbox"

	Report (ConfigureRegistry -item `
		"HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" `
		-property "DriverLoadPolicy" -type "DWord" -value 1) `
		"Run Early Launch AntiMalware"

	$O = 0
	ReportMulti "Enable Attack surface reduction rules" (ConfigureASRRules `
			-rules @{
		"56A863A9-875E-4185-98A7-B882C64B5CE5" = @(1,
			("Block abuse of exploited vulnerable signed drivers"), ++$O)
		"7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = @(1,
			("Block Adobe Reader from creating child processes"), ++$O)
		"D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = @(1,
			("Block all Office applications from creating child processes"),
			++$O)
		"9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = @(1,
			("Block credential stealing from the Windows " +
			"local security authority subsystem (lsass.exe)"), ++$O)
		"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = @(1,
			("Block executable content from email client and webmail"), ++$O)
		"01443614-CD74-433A-B99E-2ECDC07BFC25" = @(
			(GetDesiredPrevalenceAgeOrTrustedListCriterion),
			(GetDesiredPrevalenceAgeOrTrustedListCriterionDescription), ++$O)
		"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = @(1,
			("Block execution of potentially obfuscated scripts"), ++$O)
		"D3E037E1-3EB8-44C8-A917-57927947596D" = @(1,
			("Block JavaScript or VBScript from launching " +
			"downloaded executable content"), ++$O)
		"3B576869-A4EC-4529-8536-B80A7769E899" = @(1,
			("Block Office applications from creating executable content"),
			++$O)
		"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = @(1,
			("Block Office applications from injecting code " +
			"into other processes"), ++$O)
		"26190899-1602-49E8-8B27-EB1D0A1CE869" = @(1,
			("Block Office communication application from " +
			"creating child processes"), ++$O)
		"E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = @(1,
			("Block persistence through WMI event subscription"), ++$O)
		"D1E49AAC-8F56-4280-B9BA-993A6D77406C" = @(1,
			("Block process creations originating from " +
			"PSExec and WMI commands"), ++$O)
		"B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = @(1,
			("Block untrusted and unsigned processes that run from USB"), ++$O)
		"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = @(1,
			("Block Win32 API calls from Office macros"), ++$O)
		"C1DB55AB-C21A-4637-BB3F-A12568109D35" = @(1,
			("Use advanced protection against ransomware"), ++$O)
	})

	ReportMulti "Configure Windows Defender preferences" @(
		@((ConfigureMpPreference -preference "DisableRealtimeMonitoring" `
			-value $false), "Turn on real-time protection"),
		@((ConfigureMpPreference -preference "DisableBehaviorMonitoring" `
			-value $false), "Turn on behavior monitoring"),
		@((ConfigureMpPreference -preference "DisableIOAVProtection" `
			-value $false), "Scan all downloaded files and attachments"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows Defender\Real-Time Protection") `
			-property "DisableOnAccessProtection" -value $VOID),
			"Monitor file and program activity"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows Defender\Real-Time Protection") `
			-property "DisableRawWriteNotification" -value $VOID),
			"Turn on raw volume write notifications"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows Defender\Real-Time Protection") `
			-property "DisableScanOnRealtimeEnable" -value $VOID), (
			"Turn on process scanning whenever " +
				"real-time protection is enabled")),
		@((ConfigureMpPreference -preference "RealTimeScanDirection" `
			-value 0), ("Configure monitoring for " +
				"incoming and outgoing file and program activity")),
		@((ConfigureMpPreference -preference "PUAProtection" -value 1),
			"Detect and block potentially unwanted applications"),
		@((ConfigureMpPreference -preference "DisableScriptScanning" `
			-value $false), "Enable script scanning"),
		@((ConfigureMpPreference -preference "ScanAvgCPULoadFactor" -value 50),
			"Limit maximum CPU load during a scan"),
		@((ConfigureMpPreference -preference "MAPSReporting" -value 2),
			"Enable Microsoft Active Protection Service"),
		@((ConfigureMpPreference -preference "SubmitSamplesConsent" -value 1),
			"Enable automatic sample submission"),
		@((ConfigureMpPreference -preference "CloudBlockLevel" `
			-value (GetDesiredBlockingLevel)),
			"Enable cloud-delivered protection"),
		@((ConfigureMpPreference -preference "DisableBlockAtFirstSeen" `
			-value $false), "Block at first sight"),
		@((ConfigureMpPreference -preference "CloudExtendedTimeout" `
			-value 50), "Enable extended cloud check"),
		@((ConfigureMpPreference -preference "EnableNetworkProtection" `
			-value 1), "Enable Windows Defender Network Protection")
	)

	Report (ConfigureExploitMitigations) "Enable exploit mitigations"

	ReportMulti "Configure Windows SmartScreen" @(
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
			-property "EnableSmartScreen" -type "DWord" -value 1),
			"Enable Windows SmartScreen"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
			-property "ShellSmartScreenLevel" -type "String" -value "Warn"),
			"Warn the user that the app appears suspicious"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
			-property "SmartScreenEnabled" -type "String" -value "Prompt"),
			"Warn before running an unrecognized app")
	)

	$O = 0
	ReportMulti "Refine Local Security Policy" (ConfigureSecurityPolicy @{
		"Privilege Rights" = @{
			"SeDebugPrivilege" = @((ArrayToSet @(
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Disable the possibility to debug arbitrary processes"), ++$O)
			"SeLockMemoryPrivilege" = @((ArrayToSet @(
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Disallow any account to lock pages in memory"), ++$O)
			"SeTcbPrivilege" = @((ArrayToSet @(
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Prohibit accounts from acting as part of the operating " +
				"system"), ++$O)
			"SeEnableDelegationPrivilege" = @((ArrayToSet @(
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Disallow computer and user accounts to be trusted for " +
				"delegation"), ++$O)
			"SeCreateTokenPrivilege" = @((ArrayToSet @(
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Prohibit accounts from creating a token"), ++$O)
			"SeImpersonatePrivilege" = @((ArrayToSet @(
				"*S-1-5-19", "*S-1-5-20", "*S-1-5-32-544", "*S-1-5-6"
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Allow only appropriate accounts to impersonate a client " +
				"after authentication"), ++$O)
			"SeSecurityPrivilege" = @((ArrayToSet @(
				"*S-1-5-32-544"
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Allow only Administrators to manage auditing and " +
				"security log"), ++$O)
			"SeDenyNetworkLogonRight" = @((ArrayToSet @(
				"*S-1-5-7", (GetDefaultAdministrator).Name, "*S-1-5-32-546"
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Deny inappropriate accounts to access this computer " +
				"from the network"), ++$O)
			"SeNetworkLogonRight" = @((ArrayToSet @(
				"*S-1-5-32-544", "*S-1-5-32-545"
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Allow only Users and Administrators to access this " +
				"computer from the network"), ++$O)
			"SeDenyRemoteInteractiveLogonRight" = @((ArrayToSet @(
				"*S-1-5-32-546"
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Deny Guests to log on through Remote Desktop Services"), ++$O)
			"SeRemoteInteractiveLogonRight" = @((ArrayToSet @(
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Allow no one to log on through Remote Desktop Services"),
				++$O)
			"SeDenyInteractiveLogonRight" = @((ArrayToSet @(
				"*S-1-5-32-546"
				)), ${function:CommaStrToSet}, ${function:SetToCommaStr},
				("Deny Guests to log on locally"), ++$O)
		}
	})

	ReportMulti "Block remote access" @(
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows NT\Terminal Services") `
			-property "fAllowUnsolicited" -type "DWord" -value 0),
			"Prevent unsolicited remote assistance offers"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows NT\Terminal Services") `
			-property "fAllowToGetHelp" -type "DWord" -value 0),
			"Disallow solicited remote assistance"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows NT\Terminal Services") `
			-property "fDenyTSConnections" -type "DWord" -value 1),
			"Prevent users from connecting to a computer using RDS"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Policies\Microsoft\" +
				"Windows\WinRM\Service\WinRS") `
			-property "AllowRemoteShellAccess" -type "DWord" -value 0),
			"Disallow Remote Shell access"),
		@((ConfigureService -name "RemoteRegistry" -startup "Disabled" `
			-state "Stopped"), "Disable RemoteRegistry service"),
		@((ConfigureService -name "WinRM" -startup "Disabled" `
			-state "Stopped"), "Disable WinRM service")
	)

	ReportMulti "Configure User Account Control" @(
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Microsoft\Windows\" +
				"CurrentVersion\Policies\System") `
			-property "ConsentPromptBehaviorAdmin" -type "DWord" -value 2),
			"Prompt the administrator for consent on the secure desktop"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Microsoft\Windows\" +
				"CurrentVersion\Policies\System") `
			-property "ConsentPromptBehaviorUser" -type "DWord" -value 1),
			"Prompt the user for credentials on the secure desktop"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Microsoft\Windows\" +
				"CurrentVersion\Policies\System") `
			-property "EnableLUA" -type "DWord" -value 1), (
			"Notify the user when programs try to make " +
				"changes to the computer")),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Microsoft\Windows\" +
				"CurrentVersion\Policies\System") `
			-property "EnableVirtualization" -type "DWord" -value 1),
			"Virtualize file and registry write failures to per-user locations")
	)

	ReportMulti "Strengthen potentially vulnerable system options" @(
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
			-property "SafeDLLSearchMode" -type "DWord" -value 1),
			"Enable Safe DLL search mode"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
			-property "ProtectionMode" -type "DWord" -value 1),
			"Strengthen default permissions of internal system objects"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
			-property "NoDataExecutionPrevention" -value $VOID),
			"Enable Explorer Data Execution Prevention"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
			-property "NoHeapTerminationOnCorruption" -value $VOID),
			"Enable Explorer heap termination on corruption"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Microsoft\Windows\" +
				"CurrentVersion\Policies\Explorer") `
			-property "PreXPSP2ShellProtocolBehavior" -value $VOID),
			"Run Explorer shell protocol in protected mode")
	)

	ReportMulti "Strengthen potentially vulnerable network options" @(
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" `
			-property "fMinimizeConnections" -value $VOID), (
			"Limit simultaneous connections to the Internet " +
				"or a Windows domain")),
		@((ConfigureService -name "lmhosts" -startup "Disabled"),
			"Disable lmhosts service"),
		@((ConfigureService -name "NetBIOS" -startup "Disabled"),
			"Disable NetBIOS service"),
		@((ConfigureService -name "NetBT" -startup "Disabled"),
			"Disable NetBT service"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
			-property "EnableMulticast" -type "DWord" -value 0),
			"Disable link local multicast name resolution"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
			-property "DisableIPSourceRouting" -type "DWord" -value 2),
			"Prevent IP source routing"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
			-property "DisableIPSourceRouting" -type "DWord" -value 2),
			"Prevent IPv6 source routing"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
			-property "EnableICMPRedirect" -type "DWord" -value 0),
			"Disallow ICMP redirects to override OSPF generated routes"),
		@((ConfigureRegistry -item ("HKLM:\SOFTWARE\Microsoft\Windows\" +
				"CurrentVersion\Policies\System\Kerberos\Parameters") `
			-property "SupportedEncryptionTypes" -type "DWord" `
			-value 2147483640), "Prevent the use of DES and RC4 in Kerberos"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
			-property "SealSecureChannel" -type "DWord" -value 1),
			"Outgoing traffic on a secure channel should be encrypted"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
			-property "RequireSignOrSeal" -type "DWord" -value 1), (
			"Outgoing traffic on a secure channel must be " +
				"either signed or sealed")),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
			-property "fEncryptRPCTraffic" -type "DWord" -value 1),
			"Require secure RPC communications for Remote Desktop"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
			-property "MinEncryptionLevel" -type "DWord" -value 3),
			"Encrypt Remote Desktop Services sessions in both directions"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
			-property "RestrictNullSessAccess" -type "DWord" -value 1),
			"Restrict anonymous access to named pipes and shares"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "RestrictAnonymousSAM" -type "DWord" -value 1),
			"Disallow anonymous enumeration of SAM accounts"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "RestrictAnonymous" -type "DWord" -value 1),
			"Restrict anonymous enumeration of shares"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "EveryoneIncludesAnonymous" -type "DWord" -value 0), (
			"Prevent anonymous users from having the same rights " +
				"as the Everyone group")),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "RestrictRemoteSAM" -type "String" `
			-value "O:BAG:BAD:(A;;RC;;;BA)"), (
			"Allow only Administrators to remotely call " +
				"the Security Account Manager")),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "UseMachineId" -type "DWord" -value 1),
			"Allow Local System to use computer identity for NTLM"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "LimitBlankPasswordUse" -type "DWord" -value 1), (
			"Prevent access from the network to local " +
				"accounts with blank passwords")),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" `
			-property "AllowNullSessionFallback" -type "DWord" -value 0),
			"Prevent NTLM from falling back to a Null session"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
			-property "RequireSecuritySignature" -type "DWord" -value 1),
			"Configure SMB server to always perform SMB packet signing"),
		@((ConfigureRegistry -item ("HKLM:\SYSTEM\CurrentControlSet\" +
				"Services\LanmanWorkstation\Parameters") `
			-property "RequireSecuritySignature" -type "DWord" -value 1),
			"Configure SMB client to always perform SMB packet signing"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
			-property "AllowUnencryptedTraffic" -type "DWord" -value 0),
			"Disallow unencrypted WinRM service traffic"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
			-property "AllowDigest" -type "DWord" -value 0),
			"Disallow WinRM client digest authentication"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
			-property "RestrictRemoteClients" -type "DWord" -value 1),
			("Restrict unauthenticated RPC clients from " +
				"connecting to the RPC server"))
	)

	ReportMulti "Enable credential protection measures" @(
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
			-property "CachedLogonsCount" -type "String" -value "0"),
			"Disable caching of logon credentials"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
			-property "RunAsPPL" -type "DWord" -value 1),
			"Enable additional LSA protection"),
		@((ConfigureRegistry -item `
			"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
			-property "UseLogonCredential" -type "DWord" -value 0),
			"Disable WDigest authentication"),
		@((ConfigureRegistry -item `
			"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
			-property "AllowProtectedCreds" -type "DWord" -value 1), (
			"Enable `"Remote host allows delegation of " +
				"non-exportable credentials`""))
	)

	if (ArgNoAutoRebootWithLoggedOnUsers) {
		ReportMulti ("Do not reboot after an update installation " +
				"if a user is logged on") (
			@((ConfigureRegistry -item `
				"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
				-property "SetActiveHours" -type "DWord" -value 0), (
				"Disable automatic restart after updates " +
					"outside of active hours")),
			@((ConfigureRegistry -item `
				"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
				-property "AUOptions" -type "DWord" -value 4),
				"Automatically download and schedule installation of updates"),
			@((ConfigureRegistry -item `
				"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
				-property "NoAutoRebootWithLoggedOnUsers" `
				-type "DWord" -value 1), (
				"Do not reboot after an update installation " +
					"if a user is logged on")),
			@((ConfigureRegistry -item `
				"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
				-property "ScheduledInstallTime" -type "DWord" -value 3),
				"Schedule update installation time to a specific hour"),
			@((ConfigureRegistry -item `
				"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
				-property "AlwaysAutoRebootAtScheduledTime" `
				-type "DWord" -value 0), (
				"Disable automatic reboot after update installation " +
					"at scheduled time"))
		)
	}

	$local:AMStatus = Get-MpComputerStatus

	$reports = @(
		@((PCCheck (ConfirmConstrainedMode)),
			"PowerShell is configured to run in Constrained Language mode"),
		@((PCCheck (EQ $AMStatus.AMServiceEnabled $true)),
			"Antimalware Engine is enabled"),
		@((PCCheck (EQ $AMStatus.AntispywareEnabled $true)),
			"Antispyware protection is enabled"),
		@((PCCheck (EQ $AMStatus.AntivirusEnabled $true)),
			"Antivirus protection is enabled"),
		@((PCCheck (EQ $AMStatus.BehaviorMonitorEnabled $true)),
			"Behavior monitoring is enabled"),
		@((PCCheck (EQ $AMStatus.IoavProtectionEnabled $true)),
			"All downloaded files and attachments are scanned"),
		@((PCCheck (EQ $AMStatus.NISEnabled $true)),
			"NRI Engine is enabled"),
		@((PCCheck (EQ $AMStatus.OnAccessProtectionEnabled $true)),
			"File and program activity monitoring is enabled"),
		@((PCCheck (EQ $AMStatus.RealTimeProtectionEnabled $true)),
			"Real-time protection is enabled"),
		@((PCCheck (EQ $AMStatus.RealTimeScanDirection 0)),
			"Both incoming and outgoing files are scanned"),
		@((PCCheck ("Normal" -ieq $AMStatus.AMRunningMode)),
			"Antimalware running mode is Normal"),
		@((PCCheck (EQ $AMStatus.IsTamperProtected $true)),
			"Windows Defender tamper protection is enabled")
	)

	if (HasSecureBoot) {
		$reports += @(, @((PCCheck (ConfirmSecureBoot)),
			"Secure Boot is active"))
	}

	if (HasHypervisor) {
		$reports += @(, @((PCCheck `
			(EQ $DGStatus.VirtualizationBasedSecurityStatus 2)),
			"Virtualization Based Security is active"))
	}

	if (HasHVCI) {
		$reports += @(, @((PCCheck `
			($DGStatus.SecurityServicesRunning -contains 2)),
			"Hypervisor-protected code integrity is running"))
	}

	ReportMulti "Perform post-configuration checks" $reports
}

ConfigureAll
