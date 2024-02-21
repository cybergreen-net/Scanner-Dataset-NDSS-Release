all: clean build

test:
	go test -v ./...

build:
	@echo "Building the Scanner Binary"
	@mkdir -p bin/
	@go build -ldflags="-w -s" -gcflags=all="-l -B" -o bin/scan cmd/scan/*.go
	@go build -ldflags="-w -s" -gcflags=all="-l -B" -o bin/server cmd/server/*.go

clean:
	@echo "Removing Scanner binary"
	@mkdir -p bin/
	rm -rf bin/scan
	rm -rf bin/server
