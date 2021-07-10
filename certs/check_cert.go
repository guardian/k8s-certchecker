package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"time"
)

type ValidationResult int

const (
	Errored = iota
	NotValidYet
	WithinRange
	NearExpiry
	AfterExpiry
)

func LoadCert(certPEM []byte, description string) (*x509.Certificate, bool, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Printf("ERROR LoadCert Could not decode cert for %s, no details available", description)
		return nil, false, errors.New("could not decode PEM block")
	}

	log.Printf("DEBUG LoadCert %s loaded PEM content of type %s with headers %v", description, block.Type, block.Headers)
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		log.Printf("ERROR Could not parse cert for %s: %s", description, parseErr)
		return nil, false, parseErr
	}

	if cert.IsCA {
		log.Printf("WARNING LoadCert %s is a CA", description)
	}
	log.Printf("INFO LoadCert %s got certificate issued by %s, not before %s, not after %s", description, cert.Issuer, cert.NotBefore, cert.NotAfter)

	return cert, cert.IsCA, nil
}

// ValidateCertTimes
/*
decodes the certificate from the given PEM block and checks if it is expired or nearly expired.

returns a constant of enum ValidationResult indicating the status - Errored, NotValidYet, WithinRange, NearExpiry or AfterExpiry.

arguments:
- certPEM: byte block of the raw PEM data
- warningPeriod: time.Duration indicating the "near expiry" period.  If the cert NotAfter date is before this time added to the
current time, then the result is NearExpiry
- description: descriptive string for logging
*/
func ValidateCertTimes(cert *x509.Certificate, warningPeriod time.Duration, description string) (ValidationResult, error) {
	nowTime := time.Now()
	warnTime := nowTime.Add(warningPeriod)

	if nowTime.Before(cert.NotBefore) {
		return NotValidYet, nil
	} else if nowTime.After(cert.NotAfter) {
		return AfterExpiry, nil
	} else if warnTime.After(cert.NotAfter) {
		log.Printf("INFO LoadCert %s is %f%% used", description, PercentUsed(&cert.NotBefore, &cert.NotAfter))
		return NearExpiry, nil
	} else {
		log.Printf("INFO LoadCert %s is %f%% used", description, PercentUsed(&cert.NotBefore, &cert.NotAfter))
		return WithinRange, nil
	}
}

func PercentUsed(notBefore *time.Time, notAfter *time.Time) float64 {
	certDuration := notAfter.Sub(*notBefore)
	usedDuration := time.Now().Sub(*notBefore)
	return (usedDuration.Seconds() / certDuration.Seconds()) * 100
}
