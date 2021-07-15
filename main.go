package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/guardian/certchecker/certfinder"
	"github.com/guardian/certchecker/certs"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	homedir2 "k8s.io/client-go/util/homedir"
	"log"
	"path"
	"time"
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
	//inputFile := flag.String("input", "", "filename to read")
	kubeConfig := flag.String("kubeconfig", path.Join(homedir, ".kube", "config"), "kubeconfig file (only used if out of cluster)")
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

	foundCerts, scanErr := certfinder.ScanForCertificates(context.Background(), clientset)
	if scanErr != nil {
		log.Fatal("Could not scan for certs: ", scanErr)
	}
	log.Printf("INFO Got %d certs", len(*foundCerts))

	for _, entry := range *foundCerts {
		description := fmt.Sprintf("%s:%s", entry.Namespace, entry.SecretName)
		cert, _, err := certs.LoadCert(entry.RawCertificateData, description)
		if err != nil {
			log.Fatalf("Could not load %s as an x509 certificate: %s", description, err)
		}

		result, err := certs.ValidateCertTimes(cert, warningDuration, description)
		if err != nil {
			log.Fatalf("Could not validate %s: %s", description, err)
		}

		switch result {
		case certs.NotValidYet:
			log.Printf("%s is not valid yet", description)
		case certs.NearExpiry:
			log.Printf("%s is near expiry", description)
		case certs.AfterExpiry:
			log.Printf("%s has already expired", description)
		case certs.WithinRange:
			log.Printf("%s is OK", description)
		}
	}
}
