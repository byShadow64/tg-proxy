[CmdletBinding()]
param(
    [string]$ToolRoot,
    [switch]$Delivery,
    [switch]$DeviceTests,
    [string]$Serial,
    [switch]$VerifyToolchainOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($DeviceTests -and [string]::IsNullOrWhiteSpace($Serial)) {
    throw '-DeviceTests requires an explicit -Serial emulator-5584.'
}
if ($Serial -and -not $DeviceTests) {
    throw '-Serial is only used with -DeviceTests.'
}
if ($VerifyToolchainOnly -and $DeviceTests) {
    throw '-VerifyToolchainOnly does not run device tests.'
}

$androidRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$expectedGradleHash = '20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78'
$expectedWrapperHash = '81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f'
$expectedJdkHash = '49154292866386b2f4f09a3ecf3be07ab80a419149c84ec1d4419b9eec9e4b64'

function Find-Jdk17([string]$Root) {
    $tools = Join-Path $Root 'tools'
    if (-not (Test-Path -LiteralPath $tools)) { return $null }
    foreach ($directory in (Get-ChildItem -LiteralPath $tools -Directory -Filter 'jdk-*' | Sort-Object LastWriteTimeUtc -Descending)) {
        $release = Join-Path $directory.FullName 'release'
        if ((Test-Path -LiteralPath $release) -and (Test-Path -LiteralPath (Join-Path $directory.FullName 'bin\java.exe'))) {
            if (Get-Content -LiteralPath $release | Where-Object { $_ -match '^JAVA_VERSION="17[."]' }) {
                return $directory.FullName
            }
        }
    }
    return $null
}

$candidates = [Collections.Generic.List[string]]::new()
if ($ToolRoot) {
    $candidates.Add([IO.Path]::GetFullPath($ToolRoot))
} else {
    # MSIX may redirect LocalAppData into Codex's physical LocalCache folder.
    # Prefer this real path so the same command also works outside the app.
    $packages = Join-Path $env:USERPROFILE 'AppData\Local\Packages'
    if (Test-Path -LiteralPath $packages) {
        foreach ($package in (Get-ChildItem -LiteralPath $packages -Directory -Filter 'OpenAI.Codex_*' | Sort-Object LastWriteTimeUtc -Descending)) {
            $candidates.Add((Join-Path $package.FullName 'LocalCache\Local\TGProxyAndroidBuild'))
        }
    }
    if ($env:LOCALAPPDATA) { $candidates.Add((Join-Path $env:LOCALAPPDATA 'TGProxyAndroidBuild')) }
    $candidates.Add((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'TGProxyAndroidBuild'))
    $candidates.Add((Join-Path $env:USERPROFILE 'AppData\Local\TGProxyAndroidBuild'))
}

$selectedRoot = $null
$javaHome = $null
foreach ($candidate in ($candidates | Select-Object -Unique)) {
    $jdk = Find-Jdk17 $candidate
    if ($jdk -and (Test-Path -LiteralPath (Join-Path $candidate 'sdk\platforms\android-36\android.jar')) -and
        (Test-Path -LiteralPath (Join-Path $candidate 'sdk\build-tools\35.0.0\apksigner.bat'))) {
        $selectedRoot = (Resolve-Path -LiteralPath $candidate).Path
        $javaHome = $jdk
        break
    }
}
if (-not $selectedRoot) {
    throw 'JDK 17 and Android SDK 36/build-tools 35.0.0 were not found. Set -ToolRoot to the existing isolated TGProxyAndroidBuild folder. This script does not install system tools.'
}

$wrapper = Join-Path $androidRoot 'gradlew.bat'
$wrapperJar = Join-Path $androidRoot 'gradle\wrapper\gradle-wrapper.jar'
$wrapperProperties = Get-Content -LiteralPath (Join-Path $androidRoot 'gradle\wrapper\gradle-wrapper.properties') -Raw
if ((Get-FileHash -LiteralPath $wrapperJar -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedWrapperHash) {
    throw 'Gradle wrapper JAR does not match the pinned Gradle 8.13 checksum.'
}
if ($wrapperProperties -notmatch [regex]::Escape("distributionSha256Sum=$expectedGradleHash") -or
    $wrapperProperties -notmatch 'distributionUrl=https\\://downloads[.]gradle[.]org/distributions/gradle-8[.]13-bin[.]zip') {
    throw 'Gradle distribution URL/checksum does not match the pinned build.'
}

$environmentNames = @('JAVA_HOME', 'ANDROID_HOME', 'ANDROID_SDK_ROOT', 'ANDROID_USER_HOME', 'ANDROID_AVD_HOME', 'ANDROID_EMULATOR_HOME', 'GRADLE_USER_HOME', 'ANDROID_SERIAL')
$previousEnvironment = @{}
foreach ($name in $environmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$oldLocation = Get-Location
try {
    $env:JAVA_HOME = $javaHome
    $env:ANDROID_HOME = Join-Path $selectedRoot 'sdk'
    $env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
    $env:ANDROID_USER_HOME = Join-Path $selectedRoot 'android-user'
    $env:ANDROID_EMULATOR_HOME = Join-Path $env:ANDROID_USER_HOME 'emulator'
    $env:ANDROID_AVD_HOME = Join-Path $selectedRoot 'avd'
    $env:GRADLE_USER_HOME = Join-Path $selectedRoot 'gradle-home'
    $reportRoot = Join-Path $selectedRoot 'build-reports'
    New-Item -ItemType Directory -Path $reportRoot, $env:ANDROID_USER_HOME, $env:ANDROID_EMULATOR_HOME, $env:GRADLE_USER_HOME -Force | Out-Null
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $reportPath = Join-Path $reportRoot "toolchain-$stamp.json"
    $logPath = Join-Path $reportRoot "build-$stamp.log"
    $javaVersion = @(& (Join-Path $javaHome 'bin\java.exe') -version 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) { throw 'JDK verification failed.' }
    Set-Location -LiteralPath $androidRoot
    $gradleVersion = @(& $wrapper --version --console=plain 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0 -or ($gradleVersion -join "`n") -notmatch 'Gradle 8[.]13\b') { throw 'Gradle version verification failed.' }

    $archiveHashes = [ordered]@{}
    foreach ($archive in @(
        @{ Name = 'gradle-8.13-bin.zip'; Expected = $expectedGradleHash },
        @{ Name = 'microsoft-jdk-17.0.21.0.2-windows-x64.zip'; Expected = $expectedJdkHash }
    )) {
        $archivePath = Join-Path $selectedRoot (Join-Path 'downloads' $archive.Name)
        $actual = $null
        if (Test-Path -LiteralPath $archivePath) {
            $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $archive.Expected) { throw "Archive checksum mismatch: $($archive.Name)" }
        }
        $archiveHashes[$archive.Name] = @{ expectedSha256 = $archive.Expected; actualSha256 = $actual }
    }

    if ($DeviceTests) {
        if ($Serial -notmatch '^emulator-[0-9]+$') { throw 'Device tests are restricted to the owned Android emulator.' }
        $adb = Join-Path $env:ANDROID_HOME 'platform-tools\adb.exe'
        $devices = @(& $adb devices | Where-Object { $_ -match '^\S+\s+(device|offline|unauthorized)\s*$' })
        if ($devices.Count -ne 1 -or $devices[0] -notmatch ('^' + [regex]::Escape($Serial) + '\s+device\s*$')) {
            throw 'Device tests require exactly the selected online emulator and no other device records. No APK has been installed.'
        }
        $avdName = @(& $adb -s $Serial emu avd name)
        $ownedName = @($avdName | Where-Object { $_ -in @('TGProxyAndroidDev', 'TGProxyAndroidApi26') })
        if ($LASTEXITCODE -ne 0 -or $ownedName.Count -ne 1) { throw 'Selected serial is not an owned TG Proxy Android AVD.' }
        $ownedAvd = Join-Path $env:ANDROID_AVD_HOME ($ownedName[0] + '.avd\config.ini')
        if (-not (Test-Path -LiteralPath $ownedAvd)) { throw 'The isolated owned AVD configuration was not found.' }
        $env:ANDROID_SERIAL = $Serial
    }

    [ordered]@{
        createdUtc = [DateTime]::UtcNow.ToString('o')
        toolRoot = $selectedRoot
        javaHome = $javaHome
        javaVersion = $javaVersion
        sdkRoot = $env:ANDROID_HOME
        sdkPlatform = @(Get-Content -LiteralPath (Join-Path $env:ANDROID_HOME 'platforms\android-36\source.properties'))
        sdkBuildTools = @(Get-Content -LiteralPath (Join-Path $env:ANDROID_HOME 'build-tools\35.0.0\source.properties'))
        gradleVersion = $gradleVersion
        wrapperJarSha256 = $expectedWrapperHash
        archives = $archiveHashes
        deviceTests = [bool]$DeviceTests
        deliveryVariant = [bool]$Delivery
        selectedSerial = $Serial
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Write-Host "Toolchain verified. Private report: $reportPath"
    if ($VerifyToolchainOnly) { return }

    $propertiesPath = Join-Path $androidRoot 'local.properties'
    $propertyLines = @()
    if (Test-Path -LiteralPath $propertiesPath) {
        $propertyLines = @(Get-Content -LiteralPath $propertiesPath | Where-Object { $_ -notmatch '^\s*sdk[.]dir\s*=' })
    }
    $sdkProperty = $env:ANDROID_HOME.Replace('\', '/').Replace(':', '\:')
    @($propertyLines) + "sdk.dir=$sdkProperty" | Set-Content -LiteralPath $propertiesPath -Encoding ascii

    $variant = if ($Delivery) { 'Release' } else { 'Debug' }
    $tasks = @(':core:verifySshArtifacts', ':app:verifyHelperPayload', ':core:test', ":app:test${variant}UnitTest", ":app:assemble$variant", ":app:lint$variant")
    if ($Delivery) { $tasks += '-Ptgproxy.testBuildType=release' }
    & $wrapper @tasks --no-daemon --console=plain 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw "Build/checks failed. Private log: $logPath" }
    $variantLower = $variant.ToLowerInvariant()
    $apk = Join-Path $androidRoot "app\build\outputs\apk\$variantLower\app-$variantLower.apk"
    if ($Delivery) {
        $certificate = @(& (Join-Path $env:ANDROID_HOME 'build-tools\35.0.0\apksigner.bat') verify --print-certs $apk)
        if ($LASTEXITCODE -ne 0 -or ($certificate -join "`n") -notmatch 'Signer #1 certificate SHA-256 digest: 266924f2558b9a81571376f37d21c59310028d810fd6f1e0b2c4e064a0fc71c0') {
            throw 'Delivery APK does not retain the original development certificate; refusing device installation.'
        }
    }
    if ($DeviceTests) {
        $deviceTasks = @(":app:connected${variant}AndroidTest", '-Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true')
        if ($Delivery) {
            $deviceTasks += '-Ptgproxy.testBuildType=release'
            $deviceTasks += '-Pandroid.testInstrumentationRunnerArguments.class=io.github.byshadow64.tgproxy.ProxyServiceInstrumentedTest,io.github.byshadow64.tgproxy.SecureStoreInstrumentedTest,io.github.byshadow64.tgproxy.RegistryIdentityStoreTest,io.github.byshadow64.tgproxy.HelperSetupServiceInstrumentedTest,io.github.byshadow64.tgproxy.ActivityScreenshotPolicyInstrumentedTest'
        } else {
            $deviceTasks += '-Pandroid.testInstrumentationRunnerArguments.notClass=io.github.byshadow64.tgproxy.UpgradePersistenceInstrumentedTest,io.github.byshadow64.tgproxy.Upgrade012InstrumentedTest,io.github.byshadow64.tgproxy.DirectRuntimeInstrumentedTest,io.github.byshadow64.tgproxy.LivePairingRuntimeInstrumentedTest,io.github.byshadow64.tgproxy.LiveSshRuntimeInstrumentedTest,io.github.byshadow64.tgproxy.SshForegroundRuntimeInstrumentedTest'
        }
        & $wrapper @deviceTasks --no-daemon --console=plain 2>&1 | Tee-Object -FilePath $logPath -Append
        if ($LASTEXITCODE -ne 0) { throw "Device checks failed. Private log: $logPath" }
    }
    Write-Host "Development APK ($variantLower): $apk"
    Write-Host "SHA-256: $((Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant())"
} finally {
    Set-Location -LiteralPath $oldLocation
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process') }
}
