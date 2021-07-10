package main

import (
	"flag"
	"github.com/guardian/certchecker/certs"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {
	inputFile := flag.String("input", "", "filename to read")
	durationString := flag.String("warning", "720h", "expiry warning period")
	flag.Parse()

	if *inputFile == "" {
		log.Print("Testing, you must specify an input file")
		os.Exit(1)
	}

	warningDuration, durParseErr := time.ParseDuration(*durationString)
	if durParseErr != nil {
		log.Fatalf("Could not parse '%s' into a duration: %s", *durationString, durParseErr)
	}

	fp, openErr := os.Open(*inputFile)
	if openErr != nil {
		log.Fatalf("Could not open %s: %s", *inputFile, openErr)
	}
	defer fp.Close()
	content, readErr := ioutil.ReadAll(fp)
	if readErr != nil {
		log.Fatalf("Could not read data from %s: %s", *inputFile, readErr)
	}

	cert, _, err := certs.LoadCert(content, *inputFile)
	if err != nil {
		log.Fatalf("Could not load %s as an x509 certificate: %s", *inputFile, err)
	}

	result, err := certs.ValidateCertTimes(cert, warningDuration, *inputFile)
	if err != nil {
		log.Fatalf("Could not validate %s: %s", *inputFile, err)
	}

	switch result {
	case certs.NotValidYet:
		log.Printf("%s is not valid yet", *inputFile)
	case certs.NearExpiry:
		log.Printf("%s is near expiry", *inputFile)
	case certs.AfterExpiry:
		log.Printf("%s has already expired", *inputFile)
	case certs.WithinRange:
		log.Printf("%s is OK", *inputFile)
	}
}
