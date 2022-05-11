// Copyright 2020 Namecoin Developers GPLv3+

// Command certinject injects certificates into all configured trust stores
package main

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/hlandau/dexlogconfig"
	"github.com/hlandau/xlog"
	easyconfig "gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"github.com/namecoin/certinject"
)

var log, _ = xlog.New("certinject")

func main() {
	var (
		flagGroup = cflag.NewGroup(nil, "certinject")
		certflag  = cflag.String(flagGroup, "cert", "", "path to certificate to inject into trust store")
	)

	// read config
	config := easyconfig.Configurator{
		ProgramName: "certinject",
	}
	config.ParseFatal(nil)
	dexlogconfig.Init()

	var (
		certbytes []byte
		err       error
	)

	cert := certflag.Value()
	if cert != "" {
		log.Debugf("reading certificate: %q", cert)

		certbytes, err = ioutil.ReadFile(cert)
		if err != nil {
			log.Fatale(err, "error reading certificate")
		}

		certpem, _ := pem.Decode(certbytes)
		if certpem != nil {
			log.Debugf("user provided PEM-encoded input file; checking type...")

			if certpem.Type != "CERTIFICATE" {
				log.Fatalf("PEM type was %s, expecting CERTIFICATE", certpem.Type)
			}

			log.Debugf("PEM file is a certificate; extracting DER bytes...")

			certbytes = certpem.Bytes
		}
	}

	log.Debugf("injecting certificate...")

	certinject.InjectCert(certbytes)
	log.Debugf("injected certificate: %q", cert)
}
