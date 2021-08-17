package scep

/*
See the RFC at https://tools.ietf.org/id/draft-gutmann-scep-09.html#pkiMessage for full information
*/

/*
The client MUST use a unique string as the transaction identifier, encoded as a PrintableString, which MUST be used
for all PKI messages exchanged for a given operation such as a certificate issue.

Note that the transactionID must be unique, but not necessarily randomly generated.
For example it may be a value assigned by the CA (alongside the challengePassword) as
an equivalent to the traditional user name + password, so that the client is identified by their transactionID.
This can be useful when the client doesn't have a pre-assigned Distinguished Name that the CA can identify their
request through, for example when enrolling SCADA devices.
*/

type TransactionID string //RFC section 3.2.1.1

/*
The messageType attribute specifies the type of operation performed by the transaction.
This attribute MUST be included in all PKI messages.
Undefined message types MUST BE treated as an error.
*/

type MessageType string //RFC section 3.2.1.2
const (
	CertRep    = "3"  //Response to certificate or CRL request.
	RenewalReq = "17" //PKCS #10 certificate request authenticated with an existing certificate.
	PKCSReq    = "19" //PKCS #10 certificate request authenticated with a password.
	CertPoll   = "20" //Certificate polling in manual enrolment.
	GetCert    = "21" //Retrieve a certificate.
	GetCRL     = "22" //Retrieve a CRL.
)

/*
All response messages MUST include transaction status information, which is defined as a pkiStatus attribute:
*/

type PkiStatus string //RFC section 3.2.1.3
const (
	Success = "0" //Request granted.
	Failure = "2" //Request rejected. In this case the failInfo attribute, as defined in Section 3.2.1.4, MUST also be present.
	Pending = "3" //Request pending for manual approval.
)

/*
The failInfo attribute MUST contain one of the following failure reasons:

The failInfoText is a free-form UTF-8 text string that provides further information in the case of pkiStatus = FAILURE.
In particular it may be used to provide details on why a certificate request was not granted that go beyond what's
provided by the near-universal failInfo = badRequest status. Since this is a free-form text string intended for
interpretation by humans, implementations SHOULD NOT assume that it has any type of machine-processable content.
*/

type FailInfo string //RFC section 3.2.1.4
const (
	BadAlg          = "0" //Unrecognized or unsupported algorithm.
	BadMessageCheck = "1" //Integrity check (meaning signature verification of the CMS message) failed.
	BadRequest      = "2" //Transaction not permitted or supported.
	BadTime         = "3" //The signingTime attribute from the CMS authenticatedAttributes was not sufficiently close to the system time (this failure code is present for legacy reasons and is unlikely to be encountered in practice).
	BadCertId       = "4" //No certificate could be identified matching the provided criteria.
)
