MAKEFLAGS += --no-print-directory

GOBIN ?= $(shell go env GOPATH)/bin
GOTAGS ?= -tags huemocks

.DEFAULT_GOAL := check

.PHONE: deps
deps:
	go mod download -x

.PHONE: testdeps
testdeps: deps
	go install honnef.co/go/tools/cmd/staticcheck@2024.1.1

.PHONE: generate
generate: deps
	go generate $(GOTAGS) ./...

.PHONE: tidy
tidy:
	go mod verify
	go mod tidy

.PHONE: vet
vet: testdeps
	go vet $(GOTAGS) ./...

.PHONE: staticcheck
staticcheck: testdeps
	$(GOBIN)/staticcheck $(GOTAGS) ./...

.PHONE: lint
lint: vet staticcheck

.PHONE: test
test:
	go test $(GOTAGS) -v -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...

.PHONE: check
check: generate test lint

.PHONE: clean
clean:
	go clean ./...
