package helpers

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

func WriteJsonContent(content interface{}, w http.ResponseWriter, statusCode int) {
	contentBytes, marshalErr := json.Marshal(content)
	if marshalErr != nil {
		log.Printf("Could not marshal content for json write: %s", marshalErr)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Content-Length", strconv.FormatInt(int64(len(contentBytes)), 10))
	w.WriteHeader(statusCode)
	_, writeErr := w.Write(contentBytes)
	if writeErr != nil {
		log.Printf("Could not write content to HTTP socket: %s", writeErr)
	}
}

func ReadJsonBody(from io.Reader, to interface{}) error {
	byteContent, readErr := ioutil.ReadAll(from)
	if readErr != nil {
		return readErr
	}

	marshalErr := json.Unmarshal(byteContent, to)
	return marshalErr
}

func AssertHttpMethod(request *http.Request, w http.ResponseWriter, method string) bool {
	if request.Method != method {
		log.Printf("Got a %s request, expecting %s", request.Method, method)
		WriteJsonContent(GenericErrorResponse{"error", "wrong method type"}, w, 405)
		return false
	} else {
		return true
	}
}

/**
Breaks down the incoming request URI into a map of string->string
*/
func GetQueryParams(incomingRequestUri string) (*url.Values, error) {
	requestUri, uriParseErr := url.ParseRequestURI(incomingRequestUri)

	if uriParseErr != nil {
		log.Printf("Could not understand incoming request URI '%s': %s", incomingRequestUri, uriParseErr)
		return nil, errors.New("Invalid URI")
	}

	rtn := requestUri.Query()
	return &rtn, nil
}
