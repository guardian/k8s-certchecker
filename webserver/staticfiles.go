package main

import (
	"errors"
	"github.com/h2non/filetype"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type StaticFilesHandler struct {
	basePath string
	uriTrim  int
}

/**
removes up to `uriTrim` segments from the URI and returns the result.
*/
func (h StaticFilesHandler) getTrimmedUriPath(uri *string) (*string, error) {
	if h.uriTrim == 0 {
		return uri, nil
	} else {
		pathParts := strings.Split(*uri, "/")
		if len(pathParts) < h.uriTrim {
			return nil, errors.New("not enough parts in URL to trim")
		}
		result := strings.Join(pathParts[h.uriTrim:], "/")
		return &result, nil
	}
}

func (h StaticFilesHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	requestUrl, parseErr := url.ParseRequestURI(req.RequestURI)
	if parseErr != nil {
		log.Printf("Could not parse url %s: %s", req.RequestURI, parseErr)
		w.WriteHeader(400)
		return
	}

	trimmedUriPath, trimErr := h.getTrimmedUriPath(&requestUrl.Path)

	if trimErr != nil {
		log.Printf("Could not trim URL %s: %s", requestUrl.Path, trimErr)
		w.WriteHeader(404)
		return
	}

	fileName := h.basePath + "/" + *trimmedUriPath
	fileInfo, err := os.Stat(fileName)

	if err != nil {
		log.Printf("Could not stat '%s': %s", fileName, err)
		w.WriteHeader(404)
		return
	}

	fileTypeInfo, ftErr := filetype.MatchFile(fileName)
	var mimeType string
	if ftErr != nil {
		log.Printf("Could not determine type for %s: %s", fileName, ftErr)
		mimeType = "application/octet-stream"
	} else {
		mimeType = fileTypeInfo.MIME.Value
	}

	log.Printf("MIME type is %s", mimeType)
	f, openErr := os.Open(fileName)

	if openErr != nil {
		log.Printf("Could not get %s: %s", fileName, openErr)
		w.WriteHeader(500)
		return
	}

	w.Header().Add("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	w.Header().Add("Content-Type", mimeType)

	w.WriteHeader(200)
	_, copyErr := io.Copy(w, f)

	if copyErr != nil {
		log.Printf("Could not (fully) output %s: %s", fileName, copyErr)
	}
}
