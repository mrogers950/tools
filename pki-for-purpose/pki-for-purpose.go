package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"time"
)

var (
	chained = flag.Bool("chained", false, "Concatenate the CA cert to the server cert, used for nginx")
	outdir  = flag.String("outdir", "/tmp", "Specify output directory, default /tmp")
	purpose = flag.String("purpose", "nginx-web", "Specify usage purpose: nginx-web | ? ")
)

// create some certs.
func main() {
	flag.Parse()
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	casub := pkix.Name{
		CommonName: "NAHSOFT CA#1",
	}
	serverSubj := pkix.Name{
		CommonName: "nginxsvc",
	}

	clientSubj := pkix.Name{
		CommonName: "nginxcli",
	}

	caTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(1),
		Issuer:                casub,
		Subject:               casub,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           nil,
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: true,
		IsCA:           true,
		MaxPathLen:     0,
		MaxPathLenZero: false,
		DNSNames:       nil,
		EmailAddresses: nil,
		IPAddresses:    nil,
	}

	caCert, caKey, err := createParsedCertificate(caTemplate, caTemplate)
	if err != nil {
		log.Fatalf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	serverTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(2),
		Issuer:                casub,
		Subject:               serverSubj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: true,
		IsCA:           false,
		MaxPathLen:     0,
		MaxPathLenZero: false,
		DNSNames:       nil,
		EmailAddresses: nil,
		IPAddresses:    nil,
	}

	serverCert, serverKey, err := createParsedCertificate(serverTemplate, caCert)
	if err != nil {
		log.Fatalf("error creating certificate %s, %v", serverTemplate.Subject.CommonName, err)
	}

	clientTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(3),
		Issuer:                casub,
		Subject:               clientSubj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: true,
		IsCA:           false,
		MaxPathLen:     0,
		MaxPathLenZero: false,
		DNSNames:       nil,
		EmailAddresses: nil,
		IPAddresses:    nil,
	}

	clientCert, clientKey, err := createParsedCertificate(clientTemplate, caCert)
	if err != nil {
		log.Fatalf("error creating certificate %s, %v", clientTemplate.Subject.CommonName, err)
	}

	sname := "nginx"
	err = writeCertAndKey(caCert, caKey, "ca")
	if err != nil {
		log.Fatalf("error writing certificate/key %v", err)
	}
	err = writeCertAndKey(serverCert, serverKey, sname)
	if err != nil {
		log.Fatalf("error writing certificate/key %v", err)
	}

	err = writeCertAndKey(clientCert, clientKey, "client")
	if err != nil {
		log.Fatalf("error writing certificate/key %v", err)
	}

	if *chained {
		caFile, err := os.OpenFile(path.Join(*outdir, "ca.crt"), os.O_RDONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer caFile.Close()

		serverCertFile, err := os.OpenFile(path.Join(*outdir, sname+".crt"), os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer serverCertFile.Close()

		caBytes, err := ioutil.ReadAll(caFile)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := serverCertFile.Write(caBytes); err != nil {
			log.Fatal(err)
		}
	}
}

func writeCertAndKey(cert *x509.Certificate, key *rsa.PrivateKey, filename string) error {
	c := path.Join(*outdir, filename+".crt")
	k := path.Join(*outdir, filename+".key")
	certPath, err := os.Create(c)
	if err != nil {
		return err
	}
	defer certPath.Close()
	keyPath, err := os.Create(k)
	if err != nil {
		return err
	}
	defer keyPath.Close()

	pem.Encode(certPath, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return err
	}
	log.Printf("-- wrote %s", c)
	pem.Encode(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return err
	}
	log.Printf("-- wrote %s", k)
	return nil
}

func createParsedCertificate(template, parent *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("- created certificate %s", template.Subject.CommonName)

	return cert, key, nil
}
