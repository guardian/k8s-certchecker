package main

import (
	"context"
	"flag"
	"fmt"
	certfinder2 "github.com/guardian/certchecker/certchecker/certfinder"
	certs2 "github.com/guardian/certchecker/certchecker/certs"
	"github.com/guardian/certchecker/datapersistence"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	homedir2 "k8s.io/client-go/util/homedir"
	"log"
	"os"
	"path"
	"time"
	//add auth plugins, required to use e.g. openid connect
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func getClientset(kubeconfigPath string) *kubernetes.Clientset {
	clusterConfig, configErr := rest.InClusterConfig()
	if configErr == nil {
		return kubernetes.NewForConfigOrDie(clusterConfig)
	}
	log.Printf("INFO Could not get in-cluster configuration: %s, falling back to out-of-cluster", configErr)
	localConfig, localErr := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if localErr == nil {
		return kubernetes.NewForConfigOrDie(localConfig)
	}

	panic(fmt.Sprintf("ERROR Could not get either in-cluster configuration or out-of-cluster: %s", localErr))
}

func main() {
	homedir := homedir2.HomeDir()
	pwd, _ := os.Getwd()
	//inputFile := flag.String("input", "", "filename to read")
	kubeConfig := flag.String("kubeconfig", path.Join(homedir, ".kube", "config"), "kubeconfig file (only used if out of cluster)")
	outputPath := flag.String("out", pwd, "path to create an output record in")
	durationString := flag.String("warning", "720h", "expiry warning period")
	flag.Parse()

	//if *inputFile == "" {
	//	log.Print("Testing, you must specify an input file")
	//	os.Exit(1)
	//}

	warningDuration, durParseErr := time.ParseDuration(*durationString)
	if durParseErr != nil {
		log.Fatalf("Could not parse '%s' into a duration: %s", *durationString, durParseErr)
	}

	//fp, openErr := os.Open(*inputFile)
	//if openErr != nil {
	//	log.Fatalf("Could not open %s: %s", *inputFile, openErr)
	//}
	//defer fp.Close()
	//content, readErr := ioutil.ReadAll(fp)
	//if readErr != nil {
	//	log.Fatalf("Could not read data from %s: %s", *inputFile, readErr)
	//}

	clientset := getClientset(*kubeConfig)

	foundCerts, scanErr := certfinder2.ScanForCertificates(context.Background(), clientset)
	if scanErr != nil {
		log.Fatal("Could not scan for certs: ", scanErr)
	}
	log.Printf("INFO Got %d certs", len(*foundCerts))

	results := make([]datapersistence.CheckRecord, 0)

	for _, entry := range *foundCerts {
		description := fmt.Sprintf("%s:%s", entry.Namespace, entry.SecretName)
		cert, _, err := certs2.LoadCert(entry.RawCertificateData, description)
		if err != nil {
			log.Fatalf("Could not load %s as an x509 certificate: %s", description, err)
		}

		result, err := certs2.ValidateCertTimes(cert, warningDuration, entry.Namespace, entry.SecretName)
		if err != nil {
			log.Fatalf("Could not validate %s: %s", description, err)
		}

		results = append(results, result)
		switch result.CheckResult {
		case datapersistence.NotValidYet:
			log.Printf("%s is not valid yet", description)
		case datapersistence.NearExpiry:
			log.Printf("%s is near expiry", description)
		case datapersistence.AfterExpiry:
			log.Printf("%s has already expired", description)
		case datapersistence.WithinRange:
			log.Printf("%s is OK", description)
		case datapersistence.TooLongForChrome:
			log.Printf("%s is too long to be valid in Chrome", description)
		}
	}

	writeErr := datapersistence.WriteData(*outputPath, &results)
	if writeErr != nil {
		log.Fatalf("ERROR Could not write out final report: %s", writeErr)
	} else {
		log.Print("All done.")
	}
}
