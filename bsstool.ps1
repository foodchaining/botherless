#
# BSS Tool
# https://github.com/foodchaining/botherless
#
# Copyright: (C) 2021 foodchaining
# License: GNU GPL v3 or later
#

$ErrorActionPreference = "Stop"
Set-StrictMode -Version "3.0"

$PolA = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml"
$PolB = ".\lolbins.xml"

$ETBL91 = [byte[]][char[]]('!#$%&()*+,-./0123456789:;<=>?' +
	'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
$DTBL91 = [byte[]]::new(128)

function Divide([int]$dividend, [int]$divisor) {
	$remainder = [int]($dividend % $divisor)
	$quotient = [int](($dividend - $remainder) / $divisor)
	return @($quotient, $remainder)
}

function ByteArraysEqual($a0, $a1) {
	if (($a0 -is [array]) -and ($a1 -is [array])) {
		if ($a0.Length -ne $a1.Length)
			{ return $false }
		for ($i = 0; $i -lt $a0.Length; ++$i) {
			if ([byte]$a0[$i] -ne [byte]$a1[$i])
				{ return $false }
		}
		return $true
	}
	return $false
}

function GetBinaryContent($path) {
	return Get-Content -Path $path -Raw -Encoding "Byte"
}

function SetBinaryContent($path, $value) {
	Set-Content -Path $path -Force -Value $value -Encoding "Byte"
}

function InitDTBL91 {
	for ($i = 0; $i -lt 128; ++$i)
		{ $DTBL91[$i] = 255 }
	for ($i = 0; $i -lt 91; ++$i)
		{ $DTBL91[$ETBL91[$i]] = $i }
}

function ToArray($list) {
	if ($null -eq $list)
		{ return @() }
	else
		{ return [object[]]$list }
}

function RunDumpBytes($inlet) {
	for($i = 0; $i -lt $inlet.Length; ++$i) {
		if (($i % 80 -eq 0) -and ($i -gt 0)) {
			[byte]13
			[byte]10
		}
		[byte]$inlet[$i]
	}
}

function DumpBytes($inlet) { return ToArray (RunDumpBytes $inlet) }

function RunEncodeBase91($inlet) {
	$buf = 0
	$fill = 0

	function put2() {
		$ch2, $ch1 = Divide ($buf -band 0x1FFF) 91
		$ETBL91[$ch1]
		$ETBL91[$ch2]
	}

	for ($i = 0; $i -lt $inlet.Length; ++$i) {
		if ($fill -lt 13) {
			$buf = $buf -bor ([int]$inlet[$i] -shl $fill)
			$fill += 8
		}
		if ($fill -ge 13) {
			put2
			$buf = $buf -shr 13
			$fill -= 13
		}
	}

	if ($fill -gt 0) {
		if ($fill -ge 7)
			{ put2 }
		else
			{ $ETBL91[$buf] }
	}
}

function EncodeBase91($inlet) { return ToArray (RunEncodeBase91 $inlet) }

function RunDecodeBase91($inlet) {
	$ibuf = 0
	$ifill = 0
	$obuf = 0
	$ofill = 0

	function put2() {
		[byte]($obuf -band 0xFF)
		[byte](($obuf -shr 8) -band 0xFF)
	}

	for ($i = 0; $i -lt $inlet.Length; ++$i) {
		$ival = $DTBL91[$inlet[$i]]
		if ($ival -eq 255)
			{ continue }
		$ibuf = $ibuf -bor ([int]$ival -shl $ifill)
		$ifill += 8

		if ($ifill -eq 16) {
			$ch1 = $ibuf -band 0xFF
			$ch2 = ($ibuf -shr 8) -band 0xFF
			$ibuf = $ibuf -shr 16
			$ifill -= 16

			$oval = $ch1 + 91*$ch2
			$obuf = $obuf -bor ($oval -shl $ofill)
			$ofill += 13
			if ($ofill -ge 16) {
				put2
				$obuf = $obuf -shr 16
				$ofill -= 16
			}
		}
	}

	if ($ifill -eq 8) {
		$obuf = $obuf -bor ($ibuf -shl $ofill)
		if (($ofill -ge 10) -and ($ofill -le 15))
			{ put2; return }
		elseif (($ofill -ge 2) -and ($ofill -le 7))
			{ [byte]$obuf; return }
	} else {
		if (($ofill -ge 8) -and ($ofill -le 14))
			{ [byte]$obuf; return }
		elseif (($ofill -ge 0) -and ($ofill -le 6))
			{ return }
	}

	throw "DecodeBase91: ifill = $ifill, ofill = $ofill"
}

function DecodeBase91($inlet) { return ToArray (RunDecodeBase91 $inlet) }

function CreateWDACPolicy {

	$merged = (New-TemporaryFile).FullName
	$binary = (New-TemporaryFile).FullName

	$null = Merge-CIPolicy -OutputFilePath $merged -PolicyPaths $PolA, $PolB
	Set-RuleOption -FilePath $merged -Option 3 -Delete
	$null = ConvertFrom-CIPolicy -XmlFilePath $merged -BinaryFilePath $binary

	return GetBinaryContent -path $binary
}

function EncodeWDACPolicy($policy) {

	$tmpdir = (New-TemporaryFile).FullName + "." +
		(Get-Random -Minimum 100 -Maximum 1000)
	$null = New-Item -ItemType "Directory" -Path $tmpdir
	$binary = $tmpdir + "\SIPolicy.p7b"
	$zipfile = (New-TemporaryFile).FullName + ".zip"

	SetBinaryContent -path $binary -value $policy

	Compress-Archive -Path $binary -DestinationPath $zipfile
	$zipped = GetBinaryContent -path $zipfile

	$encoded = EncodeBase91 $zipped

	return DumpBytes $encoded
}

function DecodeWDACPolicy($encoded) {

	$tmpdir = (New-TemporaryFile).FullName + "." +
		(Get-Random -Minimum 100 -Maximum 1000)
	$null = New-Item -ItemType "Directory" -Path $tmpdir
	$binary = $tmpdir + "\SIPolicy.p7b"
	$zipfile = (New-TemporaryFile).FullName + ".zip"

	$zipped = DecodeBase91 $encoded

	SetBinaryContent -path $zipfile -value $zipped

	Expand-Archive -Path $zipfile -DestinationPath $tmpdir
	$policy = GetBinaryContent -path $binary

	return $policy
}

function DumpEncodedWDACPolicy {

	InitDTBL91

	$policy = CreateWDACPolicy
	$encoded = EncodeWDACPolicy $policy
	$decoded = DecodeWDACPolicy $encoded

	if (ByteArraysEqual $policy $decoded)
		{ ([char[]]$encoded) | Write-Host -NoNewline }
	else
		{ Write-Host "Error encoding WDAC policy" }
}

DumpEncodedWDACPolicy
