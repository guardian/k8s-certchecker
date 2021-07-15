all: webserver.linux64 webserver.macos

webserver.linux64: main.go indexhandler.go healthcheck.go helpers/errorresponse.go helpers/helpers.go helpers/jwt.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o webserver.linux64

webserver.macos: main.go indexhandler.go healthcheck.go helpers/errorresponse.go helpers/helpers.go helpers/jwt.go
	GOOS=darwin GOARCH=amd64 go build -o webserver.macos

clean:
	rm -f webserver.*

test:
	go test ./...

docker:
	docker build . -t guardianmultimedia/certchecker-webserver:DEV