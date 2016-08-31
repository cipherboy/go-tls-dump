package main

import (
	"os"
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/dsa"
	"fmt"
	"sync"
	"bytes"
	"encoding/pem"
)

var suites_i []uint16 = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
}

var suites_s []string = []string{
	"TLS_RSA_WITH_RC4_128_SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_256_CBC_SHA",
	"TLS_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}

var versions_i []uint16 = []uint16{
	tls.VersionSSL30,
	tls.VersionTLS10,
	tls.VersionTLS11,
	tls.VersionTLS12,
}

var versions_s []string = []string{
	"SSL v3.0",
	"TLS v1.0",
	"TLS v1.1",
	"TLS v1.2",
}

var supported_configs [][]int
var default_config []int
var given_certificates []*x509.Certificate

func addCertificate(cert *x509.Certificate) {
	for i := range given_certificates {
		var cmp *x509.Certificate = given_certificates[i]
		if bytes.Equal(cmp.SerialNumber.Bytes(), cert.SerialNumber.Bytes()) {
			return
		}
	}

	given_certificates = append(given_certificates, cert)
}

func AlgoString(algo x509.PublicKeyAlgorithm) string {
	if algo == x509.RSA {
		return "RSA"
	}
	if algo == x509.DSA {
		return "DSA"
	}
	if algo == x509.ECDSA {
		return "ECDSA"
	}
	return ""
}

func enumerateAcceptedConfigs(host string) {
	var wg sync.WaitGroup
	for v := range versions_i {
		for s := range suites_i {
			wg.Add(1)
			go func(s int, v int) {
				conn, err := tls.Dial("tcp", host, &tls.Config{
					InsecureSkipVerify: true,
					CipherSuites: []uint16{suites_i[s]},
					MinVersion: versions_i[v],
					MaxVersion: versions_i[v],
				})

				if err != nil {
					wg.Done()
					return
				}

				supported_configs = append(supported_configs, []int{s, v})

				cs := conn.ConnectionState()
				certs := cs.PeerCertificates

				for i := range certs {
					addCertificate(certs[i])
				}

				conn.Close()
				wg.Done()
			}(s, v)
		}
	}
	wg.Wait()
}

func defaultConfig(host string) {
	default_config = []int{-1, -1}

	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: suites_i,
		MinVersion: tls.VersionSSL30,
		MaxVersion: tls.VersionTLS12,
	})

	if err != nil {
		return
	}

	cs := conn.ConnectionState()

	for i := range suites_i {
		if suites_i[i] == cs.CipherSuite {
			default_config[0] = i
		}
	}

	for i := range versions_i {
		if versions_i[i] == cs.Version {
			default_config[1] = i
		}
	}

	conn.Close()
}

func main() {
	var host string
	var wg sync.WaitGroup

	if len(os.Args) != 2 {
		fmt.Println(os.Args, len(os.Args), " != 2")
		return
	}

	host = os.Args[1]

	wg.Add(1)
	go func() {
		enumerateAcceptedConfigs(host)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		defaultConfig(host)
		wg.Done()
	}()

	wg.Wait()

	fmt.Println("hostname:", host)
	fmt.Println("default: ", versions_s[default_config[1]], "and", suites_s[default_config[0]])
	for s := range supported_configs {
		c := supported_configs[s]
		fmt.Println("accepted:", versions_s[c[1]], "and", suites_s[c[0]])
	}

	fmt.Print("\n")

	for c := range given_certificates {
		cert := given_certificates[c]
		fmt.Println("cert[", c, "]Issuer:   ", cert.Issuer.CommonName)
		fmt.Println("cert[", c, "]Subject:  ", cert.Subject.CommonName)
		fmt.Println("cert[", c, "]Start:    ", cert.NotBefore)
		fmt.Println("cert[", c, "]End:      ", cert.NotAfter)
		fmt.Println("cert[", c, "]PubAlg:   ", AlgoString(cert.PublicKeyAlgorithm))
		fmt.Println("cert[", c, "]SigAlg:   ", cert.SignatureAlgorithm.String())

		if cert.PublicKeyAlgorithm == x509.RSA {
			var key *rsa.PublicKey = cert.PublicKey.(*rsa.PublicKey)
			fmt.Println("cert[", c, "]Exponent: ", key.E)
		} else if cert.PublicKeyAlgorithm == x509.DSA {
			var _ *dsa.PublicKey = cert.PublicKey.(*dsa.PublicKey)
		} else if cert.PublicKeyAlgorithm == x509.ECDSA {
			var _ *ecdsa.PublicKey = cert.PublicKey.(*ecdsa.PublicKey)
		}

		fmt.Println(string(pem.EncodeToMemory(&pem.Block {
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		})))
	}
}
