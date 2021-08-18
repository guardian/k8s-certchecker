package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"github.com/fullsailor/pkcs7"
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

	log.Printf("Requesting public cert from CA...")
	cacert, err := requestor.GetCACert(*serverBasePtr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Generating new private key...")

	privateKey, err := requestor.GenerateNewKey()
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

	log.Printf("Done. Generating self-signed cert for initial transfer...")
	sscert, err := requestor.MakeSelfSignedCert(csr, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Done. Building new cert request...")
	id, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("INFO outgoing transaction id is %s", id.String())
	req, nOnceArr, err := requestor.BuildScepRequest(csr, sscert, privateKey, cacert, id, false)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Done. Sending request...")
	response, rawResponseData, err := requestor.SendRequest(*serverBasePtr, "PKIOperation", req)
	if err != nil {
		log.Fatal(err)
	}

	if response == nil {
		log.Fatal("Internal error, nil response from SendRequest")
	}
	log.Printf("Success!")

	log.Printf("%v", response.Certificate)
	log.Printf("%v", response.PKIStatus)

	decodedTid, _ := base64.StdEncoding.DecodeString(string(response.TransactionID))
	transactionUUID, _ := uuid.FromBytes(decodedTid)
	log.Printf("INFO received transaction id is %s", transactionUUID)
	if response.MessageType != scep.CertRep {
		log.Printf("WARNING received unexpected message type %s, see https://datatracker.ietf.org/doc/html/rfc8894#section-3.2.1.2 for explanation", response.MessageType)
	}

	if response.CertRepMessage == nil {
		log.Fatal("WARNING invalid cert rep response")
	}

	if bytes.Compare(response.CertRepMessage.RecipientNonce, nOnceArr) != 0 {
		log.Printf("WARNING recipientnOnce did not match sender")
	}

	//log.Printf("%v", response)

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
		p7, err := pkcs7.Parse(*rawResponseData)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Message contains %d certs", len(p7.Certificates))
		log.Printf("Message contains %d CRLs", len(p7.CRLs))
		log.Printf("Message contains %d signers", len(p7.Signers))
		for i, s := range p7.Signers {
			log.Printf("\t%d: %s", i, string(s.IssuerAndSerialNumber.IssuerName.Bytes))
		}
		log.Printf("Message contains %d bytes of inner data", len(p7.Content))
		//decryptedBytes, err := p7.Decrypt(sscert, privateKey)
		//
		//if err != nil {
		//	log.Print("Could not manually decrypt: ", err)
		//	//log.Print(string(p7.Content))

		//if err != nil {
		//	log.Fatal("Could not parse content as unencrypted: ", err)
		//}
		//log.Printf("Inner content contains %d certs", len(innerContent.Certificates))
		//log.Printf("Inner content contains %d CRLs", len(innerContent.CRLs))
		//log.Printf("Inner content contains %d signers", len(innerContent.Signers))
		//log.Printf("Inner content contains %d bytes of inner data", len(innerContent.Content))
		cert, err := x509.ParseCertificate(p7.Content)
		//	if
		//}

		if err != nil {
			log.Fatal("Unable to parse response as an x509 cert: ", err)
		}
		pemBlock := pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{},
			Bytes:   cert.Raw,
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
