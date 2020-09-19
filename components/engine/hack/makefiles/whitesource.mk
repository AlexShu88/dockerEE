WHITESOURCE_ANALYZER    ?= cloudbees/whitesource-agent:20.1.2
WHITESOURCE_API_KEY     ?= test
WHITESOURCE_TOKEN       ?= test
WHITESOURCE_CONFIG_FILE ?= $(CURDIR)/hack/makefiles/wss-unified-agent.config
WHITESOURCE_COMMAND     ?= regular
WHITESOURCE_LOG_DIR     ?= /tmp/whitesource
WHITESOURCE_SERVICE_URL ?= https://app.whitesourcesoftware.com/agent

# The sed commands are in here because the WhiteSource analyzer is bad
# at parsing vendor.conf for vndr. Instead of changing vendor.conf, which
# will result in merge conflicts, we modify the vendor file in place
whitesource-analyze:
	mkdir -p $(WHITESOURCE_LOG_DIR)
	sed -i '/^$$/d' $(CURDIR)/$*/vendor.conf
	sed -i -E 's/\s+/ /g' $(CURDIR)/$*/vendor.conf
	-docker run --rm -i \
		-v $(CURDIR)/$*:/data \
		-v $(WHITESOURCE_CONFIG_FILE):/app/wss-unified-agent.config \
		-v $(WHITESOURCE_LOG_DIR):/app/whitesource \
		$(WHITESOURCE_ANALYZER) \
		-apiKey $(WHITESOURCE_API_KEY) \
		-projectToken $(WHITESOURCE_TOKEN) \
		-wss.url $(WHITESOURCE_SERVICE_URL) \
		$(WHITESOURCE_COMMAND)
	git checkout -- $(CURDIR)/$*/vendor.conf

