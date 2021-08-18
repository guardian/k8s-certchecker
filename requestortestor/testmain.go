package main

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"github.com/google/uuid"
	"github.com/guardian/k8s-certchecker/requestor"
	"github.com/micromdm/scep/scep"
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
	response, err := requestor.SendRequest(*serverBasePtr, "PKIOperation", req)
	if err != nil {
		log.Fatal(err)
	}

	if response == nil {
		log.Fatal("Internal error, nill response from SendRequest")
	}
	log.Printf("Success!")

	log.Printf("%v", response.MessageType)

	log.Printf("%v", response.Certificate)
	log.Printf("%v", response.PKIStatus)
	log.Printf("%v", response)

	if response.MessageType != scep.CertRep {
		log.Printf("WARNING received unexpected message type %s, see https://datatracker.ietf.org/doc/html/rfc8894#section-3.2.1.2 for explanation", response.MessageType)
	}
	switch response.PKIStatus {
	case scep.FAILURE:
		// see https://datatracker.ietf.org/doc/html/rfc8894#section-3.2.1.4
		var failureString string
		switch response.FailInfo {
		case scep.BadAlg:
			failureString = "Invalid signing algorithm"
		case scep.BadMessageCheck:
			failureString = "Signature verification of the request failed"
		case scep.BadRequest:
			failureString = "Transaction not permitted or supported"
		case scep.BadTime:
			failureString = "signingTime was not close enough to system time, re-issue the request"
		case scep.BadCertID:
			failureString = "No certificate could be identified matching the provided criteria"
		}
		log.Printf("INFO Certificate issue failed: %s", failureString)
		break
	case scep.PENDING:
		log.Printf("INFO Certificate issue is in a 'pending' state, please contact the sysadmin to progress")
		break
	case scep.SUCCESS:
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
		defer f.Close()

		err = pem.Encode(f, &pemBlock)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("All done")
}
