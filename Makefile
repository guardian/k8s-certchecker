all: certchecker.linux64 certchecker.macos

certchecker.linux64: main.go certs/check_cert.go certfinder/scanner.go datapersistence/models.go datapersistence/writer.go
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o certchecker.linux64

certchecker.macos: main.go certs/check_cert.go certfinder/scanner.go datapersistence/models.go datapersistence/writer.go
	GOOS=darwin GOARCH=amd64 go build -o certchecker.macos

docker: certchecker.linux64
	docker build . -t guardianmultimedia/certchecker:DEV

clean:
	rm -f certchecker certchecker.linux64 certchecker.macos *.json