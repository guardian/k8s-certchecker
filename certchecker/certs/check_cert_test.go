package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/guardian/k8s-certchecker/datapersistence"
	"testing"
	"time"
)

func TestValidateCertTimesExpired(t *testing.T) {
	fakeStartTime, err := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	fakeEndTime, err := time.Parse(time.RFC3339, "2020-06-01T00:00:00Z")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	fakeIssuer := pkix.Name{
		Country:            []string{"GB"},
		Organization:       []string{"Test"},
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "12345",
		CommonName:         "testing.fake.cert",
		Names:              []pkix.AttributeTypeAndValue{},
		ExtraNames:         nil,
	}

	fakeCert := x509.Certificate{
		Issuer:    fakeIssuer,
		Subject:   fakeIssuer,
		NotBefore: fakeStartTime,
		NotAfter:  fakeEndTime,
	}

	warnTime := time.Duration(3600 * time.Second)

	result, err := ValidateCertTimes(&fakeCert, warnTime, "test", "test")
	if result.CheckResult != datapersistence.AfterExpiry {
		t.Errorf("ValidateCertTimes gave wrong result, expected %d (AfterExpiry) got %d", datapersistence.AfterExpiry, result.CheckResult)
	}
}
