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
	"$C = Get-Content -Path '%BOTHERLESS_FILE%' -Raw; " ^
	"$X = $C.Substring($C.LastIndexOf('P2kjEpbW5A') + 10); " ^
	"Invoke-Expression -Command $X}" & EXIT
:: P2kjEpbW5A

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$BLVersion = "0.1.0.1"

$VOID = New-Object -TypeName PSObject

$BLAllFlags = @{
	"-NoIntroWarning" = ""
	"-AllowRestrictedUserMode" = ""
	"-ForceRelocateImages" = ""
	"-NoAutoRebootWithLoggedOnUsers" = ""
	"-AuditPrevalenceAgeOrTrustedListCriterion" = ""
	"-HighPlusBlockingLevel" = ""
}

$BLFlags = $null
$DGStatus = $null
$AMStatus = $null
$PCReports = $null

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
	if (ArgForceRelocateImages) {
		return "ON"
	} else {
		return "OFF"
	}
}

function ArgNoAutoRebootWithLoggedOnUsers {
	return $BLFlags -icontains "-NoAutoRebootWithLoggedOnUsers"
}

function ArgAuditPrevalenceAgeOrTrustedListCriterion {
	return $BLFlags -icontains "-AuditPrevalenceAgeOrTrustedListCriterion"
}

function GetDesiredPrevalenceAgeOrTrustedListCriterion {
	if (ArgAuditPrevalenceAgeOrTrustedListCriterion) {
		return 2
	} else {
		return 0
	}
}

function ArgHighPlusBlockingLevel {
	return $BLFlags -icontains "-HighPlusBlockingLevel"
}

function GetDesiredBlockingLevel {
	if (ArgHighPlusBlockingLevel) {
		return 4
	} else {
		return 2
	}
}

function ReportToInt($report) {
	switch ($report) {
		$null { return 0 }
		$true { return 1 }
		$false { return 2 }
		default { return 3 }
	}
}

function PCCheck($report) {
	if ($report) {
		return $null
	} else {
		return $false
	}
}

function DumpVersion {
	Write-Host "Botherless Security Script Version" $BLVersion
}

function ConfirmWarning {
	DumpVersion
	try {
		Write-Warning "This script can enable certain Windows built-in boot-critical security options (WDAC, VBS, HVCI, ELAM, DEP, DSE, etc) which in rare cases may render the system unbootable. Proceed with caution!" -WarningAction Inquire
	} catch
		[System.Management.Automation.ParentContainsErrorRecordException]
		{ exit 1 }
}

function DumpReport($code, $info, $indent = 0) {
	for ($i = 0; $i -lt $indent; ++$i) {
		Write-Host " " -NoNewline
	}
	Write-Host "[" -NoNewline
	switch ($code) {
		0 { Write-Host "+" -NoNewline}
		1 { Write-Host "+" -NoNewline -ForegroundColor Green }
		2 { Write-Host "X" -NoNewline -ForegroundColor Red }
		default { Write-Host "?" -NoNewline -ForegroundColor Yellow -BackgroundColor Magenta }
	}
	Write-Host "] $info"
}

function DeepEqual($a0, $a1, [scriptblock]$equality) {

	if (($null -eq $a0) -and ($null -eq $a1)) {
		return $true
	}
	if (($null -eq $a0) -or ($null -eq $a1)) {
		return $false
	}

	if (($a0 -is [array]) -and ($a1 -is [array])) {
		if ($a0.Length -ne $a1.Length) {
			return $false
		}
		for ($i = 0; $i -lt $a0.Length; ++$i) {
			if (!(DeepEqual $a0[$i] $a1[$i] $equality)) {
				return $false
			}
		}
		return $true
	}
	if (($a0 -is [array]) -or ($a1 -is [array])) {
		return $false
	}

	if (($a0 -is [hashtable]) -and ($a1 -is [hashtable])) {
		if ($a0.Count -ne $a1.Count) {
			return $false
		}
		foreach ($it in $a0.GetEnumerator()) {
			if (!(DeepEqual $it.value $a1[$it.key] $equality)) {
				return $false
			}
		}
		return $true
	}
	if (($a0 -is [hashtable]) -or ($a1 -is [hashtable])) {
		return $false
	}
	
	return & $equality $a0 $a1
}

function Equal($a0, $a1) {

	function equality($a0, $a1) {
		return $a0 -eq $a1
	}

	return DeepEqual $a0 $a1 ${function:equality}
}

function EqualI($a0, $a1) {

	function equality($a0, $a1) {
		return $a0 -ieq $a1
	}

	return DeepEqual $a0 $a1 ${function:equality}
}

function EqualC($a0, $a1) {

	function equality($a0, $a1) {
		return $a0 -ceq $a1
	}

	return DeepEqual $a0 $a1 ${function:equality}
}

function EqualCT($a0, $a1) {

	function equality($a0, $a1) {
		return ($a0.GetType() -eq $a1.GetType()) -and ($a0 -ceq $a1)
	}

	return DeepEqual $a0 $a1 ${function:equality}
}

function Report($report, $info) {
	DumpReport -code (ReportToInt $report) -info $info
}

function ReportMulti($info, $reports) {
	$root = 0
	foreach ($report in $reports) {
		$code = ReportToInt $report[0]
		if ($code -gt $root) {
			$root = $code
		}
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
		return (Confirm-SecureBootUEFI) -eq $true
	} catch
		[System.UnauthorizedAccessException]
		{ }
	return $false
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

	if (EqualCT $got $value) {
		return $null
	}

	try {
		if ($value -ne $VOID) {
			if (!(Test-Path $item)) {
				$null = New-Item $item -Force
			}
			Set-ItemProperty -Path $item -Name $property -Type $type -Value $value
		} else {
			Remove-ItemProperty -Path $item -Name $property
		}
	} catch 
		[System.Security.SecurityException],
		[System.UnauthorizedAccessException]
		{ }

	$got = getter
	
	return EqualCT $got $value
}

function ConfigureMpPreference($preference, $value) {
	
	function getter {
		$got = Get-MpPreference | Select-Object -ExpandProperty $preference
		return $got
	}
	
	$got = getter

	if (EqualC $got $value) {
		return $null
	}

	try {
		$parameters = @{ $preference = $value }
		Set-MpPreference -ErrorAction "Stop" @parameters
	} catch 
		[Microsoft.Management.Infrastructure.CimException]
		{ }

	$got = getter
	
	return EqualC $got $value
}

function ConfigureASRRules($rules) {
	
	function getter {
		$prefs = Get-MpPreference
		$ids = $prefs.AttackSurfaceReductionRules_Ids
		$actions = $prefs.AttackSurfaceReductionRules_Actions
		$isarray = ($ids -is [array]) -and ($actions -is [array])
		$got = @{}
		if ($isarray -and ($ids.Length -eq $actions.Length)) {
			for ($i = 0; $i -lt $ids.Length; ++$i) {
				$got[$ids[$i]] = $actions[$i]
			}
		}
		return $got
	}
	
	$got = getter

	if (Equal $got $rules) {
		return $null
	}

	try {
		Set-MpPreference -ErrorAction "Stop" -AttackSurfaceReductionRules_Ids $rules.keys -AttackSurfaceReductionRules_Actions $rules.values
	} catch 
		[Microsoft.Management.Infrastructure.CimException]
		{ }

	$got = getter
	
	return Equal $got $rules
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
			#"CFG.StrictControlFlowGuard" = [string]$obj.CFG.StrictControlFlowGuard
			"SEHOP.Enable" = [string]$obj.SEHOP.Enable
			"SEHOP.TelemetryOnly" = [string]$obj.SEHOP.TelemetryOnly
			"Heap.TerminateOnError" = [string]$obj.Heap.TerminateOnError
		}
	}
	
	$got = getter

	if (EqualI $got $base) {
		return $null
	}

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
	if ($E.Length -ne 0) { 
		$parameters["Enable"] = $E
	}
	if ($D.Length -ne 0) { 
		$parameters["Disable"] = $D
	}
	Set-ProcessMitigation -System @parameters *> $null

	$got = getter
	
	return EqualI $got $base
}

function ConfigureBootOption($option, $value) {

	$bcdedit = "$env:windir\System32\bcdedit.exe"

	function getter {
		$pattern = '^' + [regex]::escape($option) + '\s+(\w+)$'
		$info = (& $bcdedit /enum "{current}") | Select-String -Pattern $pattern
		if (($null -ne $info) -and ($info.Matches.Length -eq 1)) {
			return $info.Matches[0].Groups[1].Value
		}
		return $null
	}
	
	$got = getter
	
	if ($got -ieq $value) {
		return $null
	}

	& $bcdedit /set "{current}" $option $value > $null

	$got = getter
	
	return $got -ieq $value
}

function ConfigurePowerShellPolicy($value) {
	
	function getter {
		$got = Get-ExecutionPolicy -Scope "LocalMachine"
		return $got
	}
	
	$got = getter

	if ($got -ieq $value) {
		return $null
	}

	try {
		Set-ExecutionPolicy -ExecutionPolicy $value -Scope "LocalMachine" -Force
	} catch 
		[System.UnauthorizedAccessException]
		{ }

	$got = getter
	
	return $got -ieq $value
}

function ConfigureService($name, $startup, $state) {

	$conf = @{"startup" = $startup; "state" = $state }
	
	function getter {
		$service = Get-Service -Name $name
		$got = @{ "startup" = $service.StartType }
		if ($null -eq $state) {
			$got["state"] = $null
		} else {
			$got["state"] = $service.Status
		}
		return $got
	}
	
	$got = getter

	if (EqualI $got $conf) {
		return $null
	}

	try {
		if ($null -eq $state) {
			Set-Service -Name $name -StartupType $startup
		} else {
			Set-Service -Name $name -StartupType $startup -Status $state
		}
	} catch 
		[Microsoft.PowerShell.Commands.ServiceCommandException]
		{ }

	$got = getter
	
	return EqualI $got $conf
}

function ConfigureWDAC() {

	$wdac = "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"
	$base = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml"
	$temp = (New-TemporaryFile).FullName
	
	try {
		$null = ConvertFrom-CIPolicy -XmlFilePath $base -BinaryFilePath $temp
	} catch
		[System.Management.Automation.CommandNotFoundException]
		{ return $VOID }
	
	$policy = Get-Content -Path $temp -Raw

	function getter {
		try {
			$actual = Get-Content -Path $wdac -Raw
		} catch 
			[System.Management.Automation.ItemNotFoundException],
			[System.UnauthorizedAccessException]
			{ $actual = $null }
		return $actual
	}
	
	$got = getter

	if ($got -ceq $policy) {
		return $null
	}

	try {
		Copy-Item -Path $temp -Destination $wdac -Force
	} catch 
		[System.UnauthorizedAccessException]
		{ }

	$got = getter
	
	return $got -ceq $policy
}

function ConfigureOptionalFeature($feature, $value) {
	
	function getter {
		try {
			$obj = Get-WindowsOptionalFeature -Online -FeatureName $feature
			return $obj.State -ine "Disabled"
		} catch
			[System.Runtime.InteropServices.COMException]
			{ return $null }
	}
	
	$got = getter

	if ($got -eq $value) {
		return $null
	}

	try {
		if ($value) {
			$null = Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -WarningAction "SilentlyContinue"
		} else {
			$null = Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -WarningAction "SilentlyContinue"
		}
	} catch 
		[System.Runtime.InteropServices.COMException]
		{ }

	$got = getter
	
	return $got -eq $value
}

function ConfigureAll {

	$BLFlags = ($env:BOTHERLESS_ARGS -split " ").Trim().Where({$_})

	foreach ($flag in $BLFlags) {
		if (!$BLAllFlags.ContainsKey($flag)) {
			Write-Host "Bad parameter $flag"
			exit 1
		}
	}

	$OSBuild = [int](Get-WmiObject Win32_OperatingSystem).BuildNumber

	if ($OSBuild -lt 19041) {
		Write-Host "At least 20H1 version of Windows is required"
		exit 1
	}

	if (!(ArgNoIntroWarning)) {
		ConfirmWarning
	}

	$DGStatus = Get-CimInstance -ClassName "Win32_DeviceGuard" -Namespace "root\Microsoft\Windows\DeviceGuard"

	Report (ConfigureWDAC) "Configure Windows Defender Application Control"

	Report (ConfigureBootOption -option "nx" -value "AlwaysOn") "Enable DEP for the operating system and all processes"

	if (!(HasSecureBoot)) {
		Report (ConfigureBootOption -option "nointegritychecks" -value "No") "Enable Driver Signature Enforcement"
	}

	if (HasHypervisor) {
		$reports = (
			((ConfigureBootOption -option "hypervisorlaunchtype" -value "Auto"), "Enable VBS boot option"),
			((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -property "EnableVirtualizationBasedSecurity" -type DWord -value 1), "Enable VBS registry option")
		)
		if (HasSecureBootWithDMA) {
			$reports += (, ((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -property "RequirePlatformSecurityFeatures" -type DWord -value 1), "Require Secure Boot with DMA"))
		} elseif (HasSecureBoot) {
			$reports += (, ((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -property "RequirePlatformSecurityFeatures" -type DWord -value 3), "Require Secure Boot"))
		}
		ReportMulti "Enable Virtualization Based Security" $reports
	}

	if (HasHVCI) {
		Report (ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -property "Enabled" -type DWord -value 1) "Enable hypervisor-assisted protection of Code Integrity policies"
	}

	ReportMulti "Disable deprecated Windows components" (
		((ConfigureOptionalFeature -feature "SMB1Protocol" -value $false), "Disable SMB 1.0/CIFS File Sharing Support"),
		((ConfigureOptionalFeature -feature "MicrosoftWindowsPowerShellV2Root" -value $false), "Disable Windows PowerShell 2.0")
	)

	ReportMulti "Restrict Windows scripting environment" (
		((ConfigurePowerShellPolicy -value "Restricted"), "(1/3) Restrict PowerShell execution policy"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -property "ExecutionPolicy" -type String -value "Restricted"), "(2/3) Restrict PowerShell execution policy"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -property "EnableScripts" -type DWord -value 0), "(3/3) Restrict PowerShell execution policy"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -property "Enabled" -type DWord -value 0), "(1/2) Disable Windows Script Host"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings" -property "Enabled" -type DWord -value 0), "(2/2) Disable Windows Script Host")
	)

	Report (ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -property "MP_FORCE_USE_SANDBOX" -type String -value "1") "Run Windows Defender in a sandbox"

	Report (ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -property "DriverLoadPolicy" -type DWord -value 1) "Run Early Launch AntiMalware"

	Report (ConfigureASRRules -rules @{
		"56A863A9-875E-4185-98A7-B882C64B5CE5" = 1 # Block abuse of exploited vulnerable signed drivers
		"7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1 # Block Adobe Reader from creating child processes
		"D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1 # Block all Office applications from creating child processes
		"9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1 # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
		"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1 # Block executable content from email client and webmail
		"01443614-CD74-433A-B99E-2ECDC07BFC25" = GetDesiredPrevalenceAgeOrTrustedListCriterion # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
		"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1 # Block execution of potentially obfuscated scripts
		"D3E037E1-3EB8-44C8-A917-57927947596D" = 1 # Block JavaScript or VBScript from launching downloaded executable content
		"3B576869-A4EC-4529-8536-B80A7769E899" = 1 # Block Office applications from creating executable content
		"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1 # Block Office applications from injecting code into other processes
		"26190899-1602-49E8-8B27-EB1D0A1CE869" = 1 # Block Office communication application from creating child processes
		"E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1 # Block persistence through WMI event subscription
		"D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1 # Block process creations originating from PSExec and WMI commands
		"B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1 # Block untrusted and unsigned processes that run from USB
		"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1 # Block Win32 API calls from Office macros
		"C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1 # Use advanced protection against ransomware
	}) "Enable Attack surface reduction rules"

	ReportMulti "Configure Windows Defender preferences" (
		((ConfigureMpPreference -preference "DisableRealtimeMonitoring" -value $false), "Turn on real-time protection"),
		((ConfigureMpPreference -preference "DisableBehaviorMonitoring" -value $false), "Turn on behavior monitoring"),
		((ConfigureMpPreference -preference "DisableIOAVProtection" -value $false), "Scan all downloaded files and attachments"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -property "DisableOnAccessProtection" -value $VOID), "Monitor file and program activity"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -property "DisableRawWriteNotification" -value $VOID), "Turn on raw volume write notifications"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -property "DisableScanOnRealtimeEnable" -value $VOID), "Turn on process scanning whenever real-time protection is enabled"),
		((ConfigureMpPreference -preference "RealTimeScanDirection" -value 0), "Configure monitoring for incoming and outgoing file and program activity"),
		((ConfigureMpPreference -preference "PUAProtection" -value 1), "Detect and block potentially unwanted applications"),
		((ConfigureMpPreference -preference "DisableScriptScanning" -value $false), "Enable script scanning"),
		((ConfigureMpPreference -preference "ScanAvgCPULoadFactor" -value 50), "Limit maximum CPU load during a scan"),
		((ConfigureMpPreference -preference "MAPSReporting" -value 2), "Enable Microsoft Active Protection Service"),
		((ConfigureMpPreference -preference "SubmitSamplesConsent" -value 1), "Enable automatic sample submission"),
		((ConfigureMpPreference -preference "CloudBlockLevel" -value (GetDesiredBlockingLevel)), "Enable cloud-delivered protection"),
		((ConfigureMpPreference -preference "DisableBlockAtFirstSeen" -value $false), "Block at first sight"),
		((ConfigureMpPreference -preference "CloudExtendedTimeout" -value 50), "Enable extended cloud check"),
		((ConfigureMpPreference -preference "EnableNetworkProtection" -value 1), "Enable Windows Defender Network Protection")
	)

	Report (ConfigureExploitMitigations) "Enable exploit mitigations"

	ReportMulti "Configure Windows SmartScreen" (
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -property "EnableSmartScreen" -type DWord -value 1), "Enable Windows SmartScreen"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -property "ShellSmartScreenLevel" -type String -value "Warn"), "Warn the user that the app appears suspicious"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -property "SmartScreenEnabled" -type String -value "Prompt"), "Warn before running an unrecognized app")
	)

	ReportMulti "Block remote access" (
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -property "fAllowUnsolicited" -type DWord -value 0), "Prevent unsolicited remote assistance offers"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -property "fAllowToGetHelp" -type DWord -value 0), "Disallow solicited remote assistance"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -property "fDenyTSConnections" -type DWord -value 1), "Prevent users from connecting to a computer using RDS"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -property "AllowRemoteShellAccess" -type DWord -value 0), "Disallow Remote Shell access"),
		((ConfigureService -name "RemoteRegistry" -startup "Disabled" -state "Stopped"), "Disable RemoteRegistry service"),
		((ConfigureService -name "WinRM" -startup "Disabled" -state "Stopped"), "Disable WinRM service")
	)

	ReportMulti "Configure User Account Control" (
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -property "ConsentPromptBehaviorAdmin" -type DWord -value 2), "Prompt the administrator for consent on the secure desktop"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -property "ConsentPromptBehaviorUser" -type DWord -value 1), "Prompt the user for credentials on the secure desktop"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -property "EnableLUA" -type DWord -value 1), "Notify the user when programs try to make changes to the computer"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -property "EnableVirtualization" -type DWord -value 1), "Virtualize file and registry write failures to per-user locations")
	)

	ReportMulti "Strengthen potentially vulnerable system options" (
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -property "SafeDLLSearchMode" -type DWord -value 1), "Enable Safe DLL search mode"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -property "ProtectionMode" -type DWord -value 1), "Strengthen default permissions of internal system objects"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -property "NoDataExecutionPrevention" -value $VOID), "Enable Explorer Data Execution Prevention"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -property "NoHeapTerminationOnCorruption" -value $VOID), "Enable Explorer heap termination on corruption"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -property "PreXPSP2ShellProtocolBehavior" -value $VOID), "Run Explorer shell protocol in protected mode")
	)

	ReportMulti "Strengthen potentially vulnerable network options" (
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -property "fMinimizeConnections" -value $VOID), "Limit simultaneous connections to the Internet or a Windows domain"),
		((ConfigureService -name "lmhosts" -startup "Disabled"), "Disable lmhosts service"),
		((ConfigureService -name "NetBIOS" -startup "Disabled"), "Disable NetBIOS service"),
		((ConfigureService -name "NetBT" -startup "Disabled"), "Disable NetBT service"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -property "EnableMulticast" -type DWord -value 0), "Disable link local multicast name resolution"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -property "DisableIPSourceRouting" -type DWord -value 2), "Prevent IP source routing"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -property "DisableIPSourceRouting" -type DWord -value 2), "Prevent IPv6 source routing"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -property "EnableICMPRedirect" -type DWord -value 0), "Disallow ICMP redirects to override OSPF generated routes"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -property "SupportedEncryptionTypes" -type DWord -value 2147483640), "Prevent the use of DES and RC4 in Kerberos"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -property "SealSecureChannel" -type DWord -value 1), "Outgoing traffic on a secure channel should be encrypted"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -property "RequireSignOrSeal" -type DWord -value 1), "Outgoing traffic on a secure channel must be either signed or sealed"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -property "fEncryptRPCTraffic" -type DWord -value 1), "Require secure RPC communications for Remote Desktop"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -property "MinEncryptionLevel" -type DWord -value 3), "Encrypt Remote Desktop Services sessions in both directions"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -property "RestrictNullSessAccess" -type DWord -value 1), "Restrict anonymous access to named pipes and shares"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "RestrictAnonymousSAM" -type DWord -value 1), "Disallow anonymous enumeration of SAM accounts"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "RestrictAnonymous" -type DWord -value 1), "Restrict anonymous enumeration of shares"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "EveryoneIncludesAnonymous" -type DWord -value 0), "Prevent anonymous users from having the same rights as the Everyone group"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "RestrictRemoteSAM" -type String -value "O:BAG:BAD:(A;;RC;;;BA)"), "Allow only Administrators to remotely call the Security Account Manager"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "UseMachineId" -type DWord -value 1), "Allow Local System to use computer identity for NTLM"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "LimitBlankPasswordUse" -type DWord -value 1), "Prevent access from the network to local accounts with blank passwords"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -property "AllowNullSessionFallback" -type DWord -value 0), "Prevent NTLM from falling back to a Null session"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -property "RequireSecuritySignature" -type DWord -value 1), "Configure SMB server to always perform SMB packet signing"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -property "RequireSecuritySignature" -type DWord -value 1), "Configure SMB client to always perform SMB packet signing"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -property "AllowUnencryptedTraffic" -type DWord -value 0), "Disallow unencrypted WinRM service traffic"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -property "AllowDigest" -type DWord -value 0), "Disallow WinRM client digest authentication"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -property "RestrictRemoteClients" -type DWord -value 1), "Restrict unauthenticated RPC clients from connecting to the RPC server")
	)

	ReportMulti "Enable credential protection measures" (
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -property "CachedLogonsCount" -type String -value "0"), "Disable caching of logon credentials"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -property "RunAsPPL" -type DWord -value 1), "Enable additional LSA protection"),
		((ConfigureRegistry -item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -property "UseLogonCredential" -type DWord -value 0), "Disable WDigest authentication"),
		((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -property "AllowProtectedCreds" -type DWord -value 1), "Enable `"Remote host allows delegation of non-exportable credentials`"")
	)

	if (ArgNoAutoRebootWithLoggedOnUsers) {
		ReportMulti "Do not reboot after an update installation if a user is logged on" (
			((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -property "SetActiveHours" -type DWord -value 0), "Disable automatic restart after updates outside of active hours"),
			((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -property "AUOptions" -type DWord -value 4), "Automatically download and schedule installation of updates"),
			((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -property "NoAutoRebootWithLoggedOnUsers" -type DWord -value 1), "Do not reboot after an update installation if a user is logged on"),
			((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -property "ScheduledInstallTime" -type DWord -value 3), "Schedule update installation time to a specific hour"),
			((ConfigureRegistry -item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -property "AlwaysAutoRebootAtScheduledTime" -type DWord -value 0), "Disable automatic reboot after update installation at scheduled time")
		)
	}

	$AMStatus = Get-MpComputerStatus

	$PCReports = (
		((PCCheck (($DGStatus.CodeIntegrityPolicyEnforcementStatus -eq 2) -and ($DGStatus.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2))), "WDAC is running in Enforced mode"),
		((PCCheck (($Host.Runspace.LanguageMode -ieq "ConstrainedLanguage") -and ($ExecutionContext.SessionState.LanguageMode -ieq "ConstrainedLanguage"))), "This script is running in Constrained Language mode"),
		((PCCheck ($AMStatus.AMServiceEnabled -eq $true)), "Antimalware Engine is enabled"),
		((PCCheck ($AMStatus.AntispywareEnabled -eq $true)), "Antispyware protection is enabled"),
		((PCCheck ($AMStatus.AntivirusEnabled -eq $true)), "Antivirus protection is enabled"),
		((PCCheck ($AMStatus.BehaviorMonitorEnabled -eq $true)), "Behavior monitoring is enabled"),
		((PCCheck ($AMStatus.IoavProtectionEnabled -eq $true)), "All downloaded files and attachments are scanned"),
		((PCCheck ($AMStatus.NISEnabled -eq $true)), "NRI Engine is enabled"),
		((PCCheck ($AMStatus.OnAccessProtectionEnabled -eq $true)), "File and program activity monitoring is enabled"),
		((PCCheck ($AMStatus.RealTimeProtectionEnabled -eq $true)), "Real-time protection is enabled"),
		((PCCheck ($AMStatus.RealTimeScanDirection -eq 0)), "Both incoming and outgoing files are scanned"),
		((PCCheck ($AMStatus.AMRunningMode -ieq "Normal")), "Antimalware running mode is Normal"),
		((PCCheck ($AMStatus.IsTamperProtected -eq $true)), "Windows Defender tamper protection is enabled")
	)

	if (HasSecureBoot) {
		$PCReports += (, ((PCCheck (ConfirmSecureBoot)), "Secure Boot is active"))
	}

	if (HasHypervisor) {
		$PCReports += (, ((PCCheck ($DGStatus.VirtualizationBasedSecurityStatus -eq 2)), "Virtualization Based Security is active"))
	}

	if (HasHVCI) {
		$PCReports += (, ((PCCheck ($DGStatus.SecurityServicesRunning -contains 2)), "Hypervisor-protected code integrity is running"))
	}

	ReportMulti "Perform post-configuration checks" $PCReports
}

ConfigureAll
