.SILENT:

.PHONY: all test race vet fmt fmt-check build bench demo check clean

BINARY := pwp

ifeq ($(OS),Windows_NT)
	BINARY := pwp.exe
endif

all: check build

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	gofmt -l .

build:
	go build -o $(BINARY) ./cmd/pwp

bench:
	go test ./internal/generate/... -run=^$$ -bench=BenchmarkGeneratePasswordLength20 -benchmem
	go test ./internal/rules/... -run=^$$ -bench=BenchmarkCheckPasswordLength20 -benchmem
	go test ./internal/dictionary/... -run=^$$ -bench=BenchmarkDictionarySearch -benchmem
	go test ./internal/dictionary/... -run=^$$ -bench=BenchmarkLoadDictionaryMillionWords -benchmem -benchtime=1x
	go test ./internal/issue/... -run=^$$ -bench=BenchmarkIssueHistoryWindow5 -benchmem
	go test ./internal/report/... -run=^$$ -bench=BenchmarkSerializeAuditReport -benchmem

demo: build
	go run ./demo --pwp ./$(BINARY)

check: test race vet fmt-check

clean:
	go clean