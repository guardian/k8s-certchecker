package helpers

import (
	"net/http"
	"testing"
)

func TestExtractAuth(t *testing.T) {
	okRequest := &http.Request{
		Header: make(map[string][]string),
	}
	okRequest.Header.Add("Authorization", "Bearer sometoken")

	result, err := extractAuth(okRequest)
	if err != nil {
		t.Error("unexpected error from extractAuth: ", err)
	} else {
		if result != "sometoken" {
			t.Error("extractAuth should have returned 'sometoken', got '", result, "'")
		}
	}
}
