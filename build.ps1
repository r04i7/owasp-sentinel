# Standalone Windows build (no Gradle). Downloads the Montoya API jar, compiles
# with javac, bundles resources, and produces dist\owasp-sentinel-1.0.0.jar.
# Requires JDK 17+ on PATH and internet on first run.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$montoyaVersion = "2023.12.1"
$montoyaJar = "lib\montoya-api-$montoyaVersion.jar"
$montoyaUrl = "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/$montoyaVersion/montoya-api-$montoyaVersion.jar"
$outJar = "dist\owasp-sentinel-1.0.0.jar"

New-Item -ItemType Directory -Force -Path lib, build\classes, dist | Out-Null

if (-not (Test-Path $montoyaJar)) {
    Write-Host "[*] Downloading Montoya API $montoyaVersion..."
    Invoke-WebRequest -Uri $montoyaUrl -OutFile $montoyaJar
}

# Locate the jar tool (Oracle's javapath shim lacks it).
$jarTool = (Get-Command jar -ErrorAction SilentlyContinue).Source
if (-not $jarTool) {
    $jarTool = Get-ChildItem "C:\Program Files\Java\jdk*\bin\jar.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $jarTool) { throw "Could not find the 'jar' tool. Install a JDK or set JAVA_HOME." }

Write-Host "[*] Compiling..."
# Pass source paths straight to javac. (Avoid an @argfile: Windows PowerShell 5.1
# writes a UTF-8 BOM that javac rejects.)
$sources = Get-ChildItem -Recurse src\main\java -Filter *.java | ForEach-Object { $_.FullName }
# PowerShell 5.1 turns a native command's stderr into terminating errors under
# ErrorActionPreference=Stop, so relax it around javac and check the exit code.
# --release 17 also suppresses the -source/-target "system modules" warning.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& javac --release 17 -cp $montoyaJar -d build\classes $sources 2>&1 | ForEach-Object { Write-Host $_ }
$code = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
if ($code -ne 0) { throw "javac failed with exit code $code" }

Write-Host "[*] Bundling resources..."
Copy-Item -Recurse -Force src\main\resources\* build\classes\

Write-Host "[*] Packaging $outJar ..."
& $jarTool --create --file $outJar -C build\classes .

Write-Host "[+] Done: $outJar"
Write-Host "    Load it in Burp: Extensions -> Add -> Extension type: Java -> select the jar."
