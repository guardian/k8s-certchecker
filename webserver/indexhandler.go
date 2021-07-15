package main

import (
	"fmt"
	"github.com/guardian/certchecker/webserver/helpers"
	"io"
	"log"
	"net/http"
	"os"
	"path"
)

type IndexHandler struct {
	HtmlRoot string
}

/**
output the index.html file
*/
func (h IndexHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	fullpath := path.Join(h.HtmlRoot, "index.html")
	statInfo, statErr := os.Stat(fullpath)
	if statErr != nil {
		log.Printf("ERROR can't serve index.html from %s: %s", h.HtmlRoot, statErr)
		response := helpers.GenericErrorResponse{
			Status: "error",
			Detail: "server misconfigured, see logs",
		}

		helpers.WriteJsonContent(response, w, 500)
		return
	}

	fp, openErr := os.Open(fullpath)
	if openErr != nil {
		log.Printf("ERROR can't serve index.html from %s: %s", h.HtmlRoot, openErr)
		response := helpers.GenericErrorResponse{
			Status: "error",
			Detail: "server misconfigured, see logs",
		}

		helpers.WriteJsonContent(response, w, 500)
		return
	}
	defer fp.Close()

	w.Header().Add("Content-Type", "text/html")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", statInfo.Size()))
	w.WriteHeader(200)
	io.Copy(w, fp)
}
