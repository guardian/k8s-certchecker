package datapersistence

import (
	"encoding/json"
	"gopkg.in/errgo.v2/fmt/errors"
	"log"
	"math/rand"
	"os"
	"path"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func getBaseFilename() string {
	podName, hostnameErr := os.Hostname()
	if hostnameErr == nil {
		return podName
	}

	return RandStringRunes(12)
}

/**
finds an available filename in the given path
*/
func getFilename(basepath string, maxTries int) (string, error) {
	baseFilename := getBaseFilename()
	var filename = baseFilename
	i := 0

	for {
		i += 1
		if i > maxTries {
			return "", errors.Newf("Could not generate a unique filename in %d attempts", maxTries)
		}
		fullpath := path.Join(basepath, filename+".json")
		_, statErr := os.Stat(fullpath)
		if os.IsNotExist(statErr) {
			return fullpath, nil
		} else if statErr != nil {
			return "", statErr
		}
		filename = baseFilename + "-" + RandStringRunes(4)
	}
}

/**
writes a record of the scan results to a json file with a unique name,
that is in the directory `basepath`
*/
func WriteData(basepath string, results *[]CheckRecord) error {
	filename, filenameErr := getFilename(basepath, 32768)
	if filenameErr != nil {
		log.Printf("ERROR WriteData could not get a filename to write to: %s", filenameErr)
		return filenameErr
	}

	finalReport := PersistenceRecord{
		CheckedAt: time.Now(),
		Results:   *results,
	}

	encodedContent, marshalErr := json.Marshal(finalReport)
	if marshalErr != nil {
		log.Printf("ERROR WriteData was passed invalid content: %s", marshalErr)
		return marshalErr
	}

	log.Printf("INFO WriteData writing report to %s", filename)
	fp, openErr := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0640)
	if openErr != nil {
		log.Printf("ERROR WriteData could not open %s for writing: %s", filename, openErr)
		return openErr
	}
	defer fp.Close()

	_, writeErr := fp.Write(encodedContent)
	if writeErr != nil {
		log.Printf("ERROR WriteData could not write content to %s: %s", filename, writeErr)
		return writeErr
	}
	return nil
}
