.PHONY: build test clean install uninstall

BINARY_NAME=security-scanner
BUILD_DIR=bin
INSTALL_PATH=/usr/local/bin
CONFIG_DIR=/etc/security-scanner

build:
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/scanner

test:
	go test -race -timeout 60s ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	install -Dm755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	install -dm755 $(CONFIG_DIR)
	install -Dm644 config.yml $(CONFIG_DIR)/config.yml
	install -Dm644 deploy/security-scanner.service /etc/systemd/system/security-scanner.service
	systemctl daemon-reload
	systemctl enable security-scanner
	systemctl start security-scanner

uninstall:
	-systemctl stop security-scanner
	-systemctl disable security-scanner
	rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	rm -rf $(CONFIG_DIR)
	rm -f /etc/systemd/system/security-scanner.service
	systemctl daemon-reload
