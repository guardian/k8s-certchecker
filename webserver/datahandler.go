package main

import (
	"github.com/guardian/k8s-certchecker/webserver/helpers"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
)

type DataHandler struct {
	DataRoot             string
	OAuthSigningCertPath string
}

/**
define a sortable interface for DirEntry
*/
type dirSlice []os.DirEntry

func (d dirSlice) Len() int {
	return len(d)
}

func (d dirSlice) Less(i, j int) bool {
	firstFileInfo, err := d[i].Info()
	if err != nil {
		return true
	}
	secondFileInfo, err := d[j].Info()
	if err != nil {
		return true
	}
	return firstFileInfo.ModTime().Before(secondFileInfo.ModTime())
}

func (d dirSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func findReports(dataRoot string) ([]string, error) {
	contents, readErr := os.ReadDir(dataRoot)
	if readErr != nil {
		return nil, readErr
	}

	files := make([]os.DirEntry, 0)

	for _, entry := range contents {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry)
		}
	}

	sort.Sort(dirSlice(files))

	filenames := make([]string, len(files))
	for i, entry := range files {
		filenames[i] = path.Join(dataRoot, entry.Name())
	}
	return filenames, nil
}

func tryToOutput(w http.ResponseWriter, filepath string) bool {
	fp, openErr := os.Open(filepath)
	if openErr != nil {
		log.Printf("ERROR DataHandler could not open '%s': %s", filepath, openErr)
		return false
	}
	defer fp.Close()
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	io.Copy(w, fp)
	return true
}

func (h DataHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Body != nil {
		defer request.Body.Close()
	}

	if !helpers.AssertHttpMethod(request, w, "GET") {
		io.Copy(ioutil.Discard, request.Body) //discard any remaining body
		return
	}

	username, validationErr := helpers.ValidateLogin(request, h.OAuthSigningCertPath)
	if validationErr != nil {
		log.Printf("ERROR DataHandler could not validate request: %s", validationErr)
		response := helpers.GenericErrorResponse{
			Status: "forbidden",
			Detail: validationErr.Error(),
		}
		helpers.WriteJsonContent(response, w, 403)
		return
	}

	log.Printf("Serving data request to %s", username)

	reports, listErr := findReports(h.DataRoot)
	if listErr != nil {
		log.Printf("ERROR DataHandler could not list data root '%s': %s", h.DataRoot, listErr)
		response := helpers.GenericErrorResponse{
			Status: "error",
			Detail: "server problem, see server logs",
		}
		helpers.WriteJsonContent(response, w, 500)
		return
	}

	if len(reports) == 0 {
		log.Printf("ERROR DataHandler no data reports in '%s'", h.DataRoot)
		response := helpers.GenericErrorResponse{
			Status: "error",
			Detail: "no data available",
		}
		helpers.WriteJsonContent(response, w, 404)
		return
	}

	wroteData := false
	for i := 0; i < len(reports); i++ {
		wroteData = tryToOutput(w, reports[i])
		if wroteData {
			break
		}
	}
	if !wroteData {
		log.Printf("ERROR DataHandler could not find any file to output")
		response := helpers.GenericErrorResponse{
			Status: "error",
			Detail: "no valid data available",
		}
		helpers.WriteJsonContent(response, w, 500)
		return
	}
}
