package scep

import "crypto/x509"
import oscp "golang.org/x/crypto/ocsp"

// https://datatracker.ietf.org/doc/html/rfc5652#section-6 section 6.1

type OriginatorInfo struct {
	Certs []x509.Certificate     //Optional
	CRLs  *RevocationInfoChoices //Optional
	s     oscp.Request
}

type EnvelopedData struct {
	Version              int             //FIXME: RFC specifies CMSVersion data type, need to check this
	OriginatorInfo       *OriginatorInfo //Optional
	RecipientInfos       *RecipientInfos
	EncryptedContentInfo *EncryptedContentInfo
	UnprotectedAttrs     *UnprotectedAttributes //Optional
}
