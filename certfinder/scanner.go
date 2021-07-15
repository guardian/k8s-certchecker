package certfinder

import (
	"context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
)

type CertData struct {
	Namespace          string
	SecretName         string
	RawCertificateData []byte
}

func ScanNamespaces(ctx context.Context, clientset *kubernetes.Clientset) (*[]v1.Namespace, error) {
	client := clientset.CoreV1().Namespaces()

	results := make([]v1.Namespace, 0)

	var continuation string
	for {
		listOpts := metav1.ListOptions{
			Continue: continuation,
		}

		result, err := client.List(ctx, listOpts)
		if err != nil {
			return nil, err
		}

		results = append(results, result.Items...)

		if result.Continue == "" {
			break
		} else {
			continuation = result.Continue
		}
	}
	return &results, nil
}

func arrayContains(needle *v1.SecretType, haystack *[]string) bool {
	for _, blade := range *haystack {
		if string(*needle) == blade {
			return true
		}
	}
	return false
}

func ScanSecrets(ctx context.Context, clientset *kubernetes.Clientset, namespace string, typesMatch []string) (*[]v1.Secret, error) {
	client := clientset.CoreV1().Secrets(namespace)

	var continuation string
	results := make([]v1.Secret, 0)

	for {
		result, err := client.List(ctx, metav1.ListOptions{
			Continue: continuation,
		})
		if err != nil {
			return nil, err
		}

		for _, secret := range result.Items {
			if arrayContains(&secret.Type, &typesMatch) {
				results = append(results, secret)
			}
		}

		if result.Continue == "" {
			break
		} else {
			continuation = result.Continue
		}
	}
	return &results, nil
}

func extractCertData(secret *v1.Secret) *[]byte {
	if tlsData, haveTlsData := secret.Data["tls.crt"]; haveTlsData {
		return &tlsData
	} else {
		return nil
	}
}

func ScanForCertificates(ctx context.Context, clientset *kubernetes.Clientset) (*[]CertData, error) {
	namespacesPtr, nsErr := ScanNamespaces(ctx, clientset)
	if nsErr != nil {
		log.Fatal("ERROR Could not scan for namespaces: ", nsErr)
	}

	log.Printf("INFO Found %d namespaces", len(*namespacesPtr))

	results := make([]CertData, 0)

	for _, namespace := range *namespacesPtr {
		log.Printf("INFO Checking %s...", namespace.Name)
		certSecrets, secretsErr := ScanSecrets(ctx, clientset, namespace.Name, []string{"Opaque", "kubernetes.io/tls"})
		if secretsErr == nil {
			log.Printf("INFO %s: found %d secrets that may be certs", namespace.Name, len(*certSecrets))
			for _, cert := range *certSecrets {
				certData := extractCertData(&cert)
				if certData != nil {
					results = append(results, CertData{
						Namespace:          namespace.Name,
						SecretName:         cert.Name,
						RawCertificateData: *certData,
					})
				}
			}
		} else {
			log.Printf("ERROR Could not scan for secrets in '%s': %s", namespace.Name, secretsErr)
		}
	}

	log.Printf("INFO All certs gathered, found a total of %d", len(results))
	return &results, nil
}
