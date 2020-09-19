$goPath = go env GOPATH

Write-Host "+ Copying docker/registry-cli to location $destDir"
$destDir = "$goPath\src\github.com\docker\registry-cli"
Copy-Item -Recurse C:\sources\Mirantis\registry-cli $destDir
Set-Location $destDir
Write-Host "+ Building docker/registry-cli"
make dynbinary
Write-Host "+ Moving docker-registry-cli.exe -> C:\out"
Move-Item -Force build\docker-registry C:\out\docker-registry.exe
