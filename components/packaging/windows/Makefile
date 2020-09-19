include ../common.mk
include ../common-ee.mk

CLI_DIR:=$(realpath $(CURDIR)/../../cli)
ENGINE_DIR:=$(realpath $(CURDIR)/../../engine)
GO_BASE_IMAGE=golang
ENGINE_GO_IMAGE=$(GO_BASE_IMAGE):$(GO_VERSION)
WINDOWS_BUILDER?=windows-engine-builder
GOPATH=C:\go
DOCKER_GOPATH=C:\gopath\src\github.com\docker
TELEMETRY_API_KEY:=MEMutJjWBF0qNOqd6pqTuDPvL07ZbHT1
DOCKER_GITCOMMIT?=$(shell git -C $ENGINE_DIR rev-parse --short HEAD)
CLI_GITCOMMIT?=$(shell git -C $CLI_DIR rev-parse --short HEAD)

clean:
	-$(RM) $(WINDOWS_BUILDER)
	-$(RM) -r docker
	-$(RM) -r sources
	-$(RM) *.zip
	-docker rmi -f $(WINDOWS_BUILDER)

$(WINDOWS_BUILDER):
	docker build -t $(WINDOWS_BUILDER) \
		--build-arg GO_IMAGE=$(ENGINE_GO_IMAGE) \
		-f Dockerfile.engine .
	echo 1 > $@

docker:
	mkdir $@

docker/dockerd.exe: docker $(WINDOWS_BUILDER)
	docker run --rm \
		-e DOCKER_GITCOMMIT="$(DOCKER_GITCOMMIT)" \
		-e VERSION="$(VERSION)" \
		-e PLATFORM="$(PLATFORM)" \
		-e TELEMETRY_API_KEY="$(TELEMETRY_API_KEY)" \
		-v "$(CURDIR)/docker:c:\out" \
		-v "$(ENGINE_DIR):$(DOCKER_GOPATH)\docker" \
		-w "$(DOCKER_GOPATH)\docker" \
		--entrypoint powershell \
		$(WINDOWS_BUILDER) \
		"hack/make.ps1 -Daemon; Move-Item bundles\dockerd.exe c:\out"

docker/docker.exe: docker $(WINDOWS_BUILDER)
	docker run --rm \
		-e DOCKER_GITCOMMIT="$(CLI_GITCOMMIT)" \
		-e VERSION="$(VERSION)" \
		-e PLATFORM="$(PLATFORM)" \
		-v "$(CURDIR)/docker:c:\out" \
		-v "$(CLI_DIR):$(DOCKER_GOPATH)\cli" \
		-w "$(DOCKER_GOPATH)\cli"\
		--entrypoint powershell \
		$(WINDOWS_BUILDER) \
		"scripts/make.ps1 -Binary; Move-Item build\docker.exe c:\out"

docker/licenses.txt: licenses.txt docker
	xcopy .\$< $(@D)

.PHONY: windows-dll
windows-dll: docker
	docker run --rm \
		-i \
		-v "$(CURDIR)/docker:c:\out" \
		-v "$(CURDIR)/scripts/:c:\scripts" \
		--entrypoint powershell \
		$(WINDOWS_BUILDER) \
		"c:\scripts\extract-dlls.ps1"

.PHONY: plugins
plugins: $(WINDOWS_BUILDER)
	powershell -File 'plugins\build_all.ps1'

.PHONY: win
win: docker-$(VERSION).zip

docker-$(VERSION).zip: docker/dockerd.exe docker/docker.exe windows-dll docker/licenses.txt plugins
	$(RM) $@
	docker run --rm \
		-v "$(CURDIR):C:\gopath" \
		-w "C:\gopath" \
		--entrypoint powershell \
		$(WINDOWS_BUILDER) \
		"Compress-Archive -Path C:/gopath/docker -DestinationPath C:/gopath/docker-$(VERSION).zip"
