package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/innoq/scep/scep"
	"io/ioutil"
	"log"
	"net/http"
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

// BuildScepRequest
/*
BuildScepRequest takes a CertificateSigningRequest and encodes a PKI Message for sending to the SCEP server.
You need to specify a UUID to use as a transaction ID, this is used to verify the response.
If the isUpdate parameter is set then the message is of type scep.UpdateReq; if not then is is of scep.PKCSReq.
*/
func BuildScepRequest(csr *x509.CertificateRequest, requestId uuid.UUID, isUpdate bool) (*scep.PKIMessage, error) {
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
	}

	return scep.NewCSRRequest(csr, template)
}

// SendRequest
// Sends a request to the SCEP server and unmarshals/parses the returned response body.
// Parameters:
//  `server`: base URL to contact, including protocol, host and port e.g. https://certserver.mycompany.com:1234
//  `operationName`: a valid SCEP operation name
//  `req`: a pointer to a constructed scep.PKIMessage body.  If this parameter is nil, a GET request is issued with no body.
//see https://tools.ietf.org/id/draft-gutmann-scep-09.html#rfc.section.4
func SendRequest(server string, operationName string, req *scep.PKIMessage) (*scep.PKIMessage, error) {
	var response *http.Response
	var err error

	requestUrl := fmt.Sprintf("%s/cgi-bin/pkiclient.exe?operation=%s", server, operationName) //see https://tools.ietf.org/id/draft-gutmann-scep-09.html#rfc.section.4
	byteBuffer := bytes.NewBuffer([]byte{})

	if req == nil {
		response, err = http.Get(requestUrl)
	} else {
		encodingErr := gob.NewEncoder(byteBuffer).Encode(*req)
		if encodingErr != nil {
			log.Printf("ERROR sendRequest could not encode to binary: %s", encodingErr)
			return nil, encodingErr
		}

		response, err = http.Post(requestUrl, "application/octet-stream", byteBuffer)
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
		return scep.ParsePKIMessage(rawResponseData)
	} else {
		return nil, errors.New(fmt.Sprintf("ERROR Server responded %d: %s", response.StatusCode, string(rawResponseData)))
	}
}
