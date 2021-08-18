package requestor

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/micromdm/scep/scep"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// GenerateNewKey
/**
Generates a new RSA key suitable for signing an SSL certificate
*/
func GenerateNewKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// MakeCSRFor
/**
Builds a Certificate Signing Request for the given target and return it or an error.
Parameters:

dn: Distinguished Name that identifies the thing needing the certificate.  This is in the form of a pkix.Name structure
alternateDnsNames: array of strings stipulating alternate DNS names for the server to be considered valid
extraExtensions: other extensions required for this cert (generally supply `nil` for this)
privateKey: pre-created private key that is required for the SSL server
*/
func MakeCSRFor(dn *pkix.Name, alternateDnsNames []string, extraExtensions []pkix.Extension, privateKey *rsa.PrivateKey) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            *dn,
		DNSNames:           alternateDnsNames,
		ExtraExtensions:    extraExtensions,
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(derBytes)
}

func MakeSelfSignedCert(signerKey *rsa.PrivateKey) (*x509.Certificate, error) {
	caTempl := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &signerKey.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}

	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &signerKey.PublicKey, signerKey)

	return x509.ParseCertificate(certBytes)
}

// BuildScepRequest
/*
BuildScepRequest takes a CertificateSigningRequest and encodes a PKI Message for sending to the SCEP server.
You need to specify a UUID to use as a transaction ID, this is used to verify the response.
If the isUpdate parameter is set then the message is of type scep.UpdateReq; if not then is is of scep.PKCSReq.
*/
func BuildScepRequest(csr *x509.CertificateRequest, signerCert *x509.Certificate, signerKey *rsa.PrivateKey, requestId uuid.UUID, isUpdate bool) (*scep.PKIMessage, error) {
	var msgType scep.MessageType
	if isUpdate {
		msgType = scep.UpdateReq
	} else {
		msgType = scep.PKCSReq
	}

	nOnceArray := make([]byte, 16)
	rand.Read(nOnceArray)

	template := &scep.PKIMessage{
		TransactionID: scep.TransactionID(requestId.String()),
		MessageType:   msgType,
		SenderNonce:   scep.SenderNonce(nOnceArray),
		SignerCert:    signerCert,
		SignerKey:     signerKey,
	}

	return scep.NewCSRRequest(csr, template)
}

// SendRequest
// Sends a request to the SCEP server and unmarshals/parses the returned response body.
// Parameters:
//  `server`: base URL to contact, including protocol, host and port e.g. https://certserver.mycompany.com:1234. Don't include a trailign /.
//  `operationName`: a valid SCEP operation name
//  `req`: a pointer to a constructed scep.PKIMessage body.  If this parameter is nil, a GET request is issued with no body.
//see https://tools.ietf.org/id/draft-gutmann-scep-09.html#rfc.section.4
func SendRequest(server string, operationName string, req *scep.PKIMessage) (*scep.PKIMessage, error) {
	var response *http.Response
	var err error

	requestUrl := fmt.Sprintf("%s/certsrv/mscep/?operation=%s", server, operationName) //see https://tools.ietf.org/id/draft-gutmann-scep-09.html#rfc.section.4

	if req == nil {
		response, err = http.Get(requestUrl)
	} else {
		reader := bytes.NewReader(req.Raw)
		response, err = http.Post(requestUrl, "application/x-pki-message", reader)
	}

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	rawResponseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode == 200 {
		log.Printf("Server responded %d with %s bytes of %s content", response.StatusCode, response.Header.Get("Content-Length"), response.Header.Get("Content-Type"))
		log.Printf("Got %d bytes of data in response", len(rawResponseData))
		return scep.ParsePKIMessage(rawResponseData)
	} else {
		return nil, errors.New(fmt.Sprintf("ERROR Server responded %d: %s", response.StatusCode, string(rawResponseData)))
	}
}
