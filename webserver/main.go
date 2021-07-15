package main

import (
	"log"
	"net/http"
	"os"
)

func getRootFromEnviron(key string) string {
	htmlRoot := os.Getenv(key)
	if htmlRoot == "" {
		log.Fatalf("You must set %s in the environment to a valid path", key)
	}
	statInfo, statErr := os.Stat(htmlRoot)
	if statErr != nil {
		log.Fatalf("%s '%s' is not valid: %s", key, htmlRoot, statErr)
	}
	if !statInfo.IsDir() {
		log.Fatalf("%s '%s' is not a directory", key, htmlRoot)
	}
	return htmlRoot
}

func main() {
	htmlRoot := getRootFromEnviron("HTML_ROOT")
	dataRoot := getRootFromEnviron("DATA_ROOT")
	indexHandler := IndexHandler{HtmlRoot: htmlRoot}
	staticHandler := StaticFilesHandler{basePath: htmlRoot, uriTrim: 2} //assuming htmlRoot points to the /static foler
	dataHandler := DataHandler{
		DataRoot:             dataRoot,
		OAuthSigningCertPath: os.Getenv("SIGNING_CERT"),
	}
	healthcheck := HealthcheckHandler{}

	http.Handle("/api/latest", dataHandler)
	http.Handle("/healthcheck", healthcheck)
	http.Handle("/static/", staticHandler)
	http.Handle("/", indexHandler)

	log.Printf("Starting server on port 9000")
	startServerErr := http.ListenAndServe(":9000", nil)

	if startServerErr != nil {
		log.Fatal(startServerErr)
	}
}
