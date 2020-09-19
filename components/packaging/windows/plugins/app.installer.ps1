$goPath = go env GOPATH

Write-Host "+ Copying docker/app to location $destDir"
$destDir = "$goPath\src\github.com\docker\app"
Copy-Item -Recurse C:\sources\docker\app $destDir
Set-Location $destDir
Write-Host "+ Building docker/app"
make dynamic
Write-Host "+ Moving docker-app.exe -> C:\out"
Move-Item -Force bin\docker-app.exe C:\out
