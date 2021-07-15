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
	indexHandler := IndexHandler{HtmlRoot: getRootFromEnviron("HTML_ROOT")}
	healthcheck := HealthcheckHandler{}

	http.Handle("/healthcheck", healthcheck)
	http.Handle("/", indexHandler)

	log.Printf("Starting server on port 9000")
	startServerErr := http.ListenAndServe(":9000", nil)

	if startServerErr != nil {
		log.Fatal(startServerErr)
	}
}
