$ErrorActionPreference = "Stop"

function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    $name = [System.IO.Path]::GetRandomFileName()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

Function CloneSource($destDir, $gitSource, $gitReference) {
    # Should clone this down into a temp directory for zipping later
    git clone -q git@github.com:$gitSource $destDir/$gitSource
    git -C $destDir/$gitSource checkout -q $gitReference
}

# Set tmpdir up here as well so the finally doesn't blow up
# if we fail creating a tmpdir
$tmpdir = ""

try {
    $tmpdir = New-TemporaryDirectory
    Write-Host "+ Created temporary directory '$tmpdir'"
    $CURDIR = Get-Location
    $plugins = Import-CSV $PSScriptRoot\plugin_sources.csv
    $installers = Get-ChildItem $PSScriptRoot -Filter *.installer.ps1

    ForEach ($plugin in $plugins) {
        Write-Host "+ Cloning $($plugin.gitSource)@$($plugin.gitReference)"
        CloneSource "$tmpdir" "$($plugin.gitSource)" "$($plugin.gitReference)"
    }

    Write-Host "+ Creating docker\cli-plugins directory"
    New-Item docker\cli-plugins -Type Directory -Force
    ForEach ($installer in $installers) {
        Write-Host "+ Executing $installer"
        docker run --rm `
            -i `
            -v "${CURDIR}/docker/cli-plugins:c:\out" `
            -v "${CURDIR}/plugins:c:\plugins" `
            -v "${tmpdir}:c:\sources" `
            --entrypoint powershell `
            windows-engine-builder `
            "c:\plugins\${installer}"
    }
} catch [Exception] {
    throw $_
} finally {
    Write-Host "+ Removing temporary directory ${tmpdir}"
    Remove-Item -Recurse -Force $tmpdir
}
