$CWD = (Get-Location)

try {
    # Make Third-Party Directory
    New-Item -ItemType Directory -Path third-party -Force
    Set-Location third-party

    # Clone libpcap 1.10.5
    git clone --depth 1 --branch libpcap-1.10.5 https://github.com/the-tcpdump-group/libpcap.git
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone libpcap." }

    # Download Npcap SDK
    Invoke-WebRequest https://npcap.com/dist/npcap-sdk-1.13.zip -OutFile npcap-sdk.zip
    Expand-Archive npcap-sdk.zip -DestinationPath npcap-sdk -Force
    Remove-Item npcap-sdk.zip

    # Download Npcap Installer 1.80
    Invoke-WebRequest https://npcap.com/dist/npcap-1.80.exe -OutFile npcap-installer.exe

    # Download winflexbison
    Invoke-WebRequest https://github.com/lexxmark/winflexbison/releases/download/v2.5.25/win_flex_bison-2.5.25.zip -OutFile winflexbison.zip
    Expand-Archive winflexbison.zip -DestinationPath winflexbison -Force
    Remove-Item winflexbison.zip

    # Build libpcap
    Set-Location libpcap
    New-Item -ItemType Directory -Path build -Force
    Set-Location build
    $env:PATH = $env:PATH + ";" + (Join-Path -Path (Get-Location) -ChildPath ../../winflexbison)
    cmake -DPacket_ROOT="../../npcap-sdk" -G "Visual Studio 17 2022" -A x64 ..
    if ($LASTEXITCODE -ne 0) { throw "Failed to configure cmake." }
    cmake --build . -- /m /nologo /p:Configuration=Release
    if ($LASTEXITCODE -ne 0) { throw "Failed to build libcap." }
    cmake --install . --prefix "../dist"
    if ($LASTEXITCODE -ne 0) { throw "Failed to install libcap." }
} catch {
    Write-Error $PSItem.Exception.Message
} finally {
    Set-Location $CWD
}
