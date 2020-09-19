<#
    This script basically extracts the dlls we want from our go-crypto-swap image and outputs them
    to our desired output directory for inclusion in our `.zip` file.
#>

$dlls = @(
    "C:\usr\local\ssl\bin\ssleay32.dll"
    "C:\usr\local\ssl\bin\libeay32.dll"
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\redist\x64\Microsoft.VC140.CRT\vcruntime140.dll"
    "C:\c\bin\libwinpthread-1.dll"
)

ForEach ($dll in $dlls) {
    Write-Host "Copying $dll -> C:\out"
    Copy-Item -Path $dll -Destination C:\out
}
