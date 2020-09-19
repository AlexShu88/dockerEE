# Variables to execute the license analysis and test across the engine
# ToDo: remove the --debug flag
BUILD_ANALYZER?=docker/fossa-analyzer
FOSSA_OPTS?=--option all-tags:true --option allow-unresolved:true --debug

fossa-analyze:
	docker run -i --rm -e FOSSA_API_KEY \
		-e GO111MODULE=off \
		-v $(CURDIR)/$*:/go/src/github.com/docker/docker \
		-w /go/src/github.com/docker/docker \
		$(BUILD_ANALYZER) analyze $(FOSSA_OPTS) --branch $(BRANCH_NAME)

fossa-test:
	docker run -i --rm -e FOSSA_API_KEY \
		-v $(CURDIR)/$*:/go/src/github.com/docker/docker \
		-w /go/src/github.com/docker/docker \
		$(BUILD_ANALYZER) test --debug

