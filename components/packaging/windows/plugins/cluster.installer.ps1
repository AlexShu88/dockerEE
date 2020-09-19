$goPath = go env GOPATH
$destDir = "$goPath\src\github.com\Mirantis\cluster"

# The build still uses the older GOPATH mode, so we have to
# explicitly disable module mode here.  If the build ever
# migrates to module mode, we can get rid of this line.
$Env:GO111MODULE = "off"

Write-Host "+ Copying Mirantis/cluster to location $destDir"
Copy-Item -Recurse C:\sources\Mirantis\cluster $destDir
Set-Location $destDir

Write-Host "+ Installing dependent tools"
# Set gopath explicitly since we use `C:\go` as the GOROOT as well
$Env:GOPATH = "C:\gopath"; go get -u github.com/go-bindata/go-bindata/...
$Env:GOPATH = $goPath

Write-Host "+ Building Mirantis/cluster"
make DIFF_STAT_CMD=';' SOURCE="" plugin ORG=mirantis

Write-Host "+ Moving docker-cluster.exe -> C:\out"
Move-Item -Force docker-cluster.exe C:\out
