.PHONY: all test test-race test-cover bench fuzz lint fmt tidy clean

all: test

test:
	go test -v -count=1 ./...

test-race:
	go test -race ./...

test-cover:
	go test -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html

bench:
	go test -bench=".*" -benchmem ./...

fuzz:
	go test -fuzz=FuzzFrameDecoder -fuzztime=10s
	go test -fuzz=FuzzHandshakeParser -fuzztime=10s
	go test -fuzz=FuzzReplayCache -fuzztime=10s
	go test -fuzz=FuzzAntiReplayWindow -fuzztime=10s
	go test -fuzz=FuzzSlidingWindowSequence -fuzztime=10s

lint:
	go vet ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy

clean:
	go clean -cache -testcache
	rm -f coverage.txt coverage.html *.test
