package main

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"github.com/google/uuid"
	"github.com/guardian/k8s-certchecker/requestor"
	"log"
	"os"
)

func main() {
	serverBasePtr := flag.String("server", "https://localhost", "NDES server to contact")
	output := flag.String("out", "testcert.pem", "PEM formatted file to output")
	flag.Parse()

	log.Printf("Generating new private key...")

	privateKey, err := requestor.GenerateNewKey()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Done. Generating self-signed cert for initial transfer...")
	sscert, err := requestor.MakeSelfSignedCert(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Done. Generating CSR....")
	dn := &pkix.Name{
		Country:            []string{"en"},
		Organization:       []string{"testcorp"},
		OrganizationalUnit: []string{"test"},
		Locality:           []string{"London"},
		Province:           []string{"London"},
		CommonName:         "test.testcorp.com",
	}
	altNames := []string{"test2.testcorp.com", "test3.testcorp.com"}

	csr, err := requestor.MakeCSRFor(dn, altNames, []pkix.Extension{}, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Done. Building new cert request...")
	id, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}

	req, err := requestor.BuildScepRequest(csr, sscert, privateKey, id, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Done. Sending request...")
	response, err := requestor.SendRequest(*serverBasePtr, "PKCSReq", req)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Success!")

	pemBlock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{},
		Bytes:   response.Certificate.Raw,
	}
	f, openErr := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if openErr != nil {
		log.Printf("ERROR can't open %s to write: %s", *output, err)
		f = os.Stdout
	}

	err = pem.Encode(f, &pemBlock)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("All done")
}
