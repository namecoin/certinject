// Copyright 2020 Namecoin Developers GPLv3+

// Command certinject injects certificates into all configured trust stores
package main

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/hlandau/xlog"
	easyconfig "gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"github.com/namecoin/certinject"
)

var log, logp = xlog.New("certinject")

func main() {
	var (
		flagGroup = cflag.NewGroup(nil, "certinject")
		certflag  = cflag.String(flagGroup, "cert", "", "path to certificate to inject into trust store")
		loglevel  = cflag.String(flagGroup, "loglevel", "info",
			"logging level (from least to most verbose: emergency, alert, critical, error, warn, notice, info, debug, trace")
	)

	// read config
	config := easyconfig.Configurator{
		ProgramName: "certinject",
	}
	config.ParseFatal(nil)

	level, ok := xlog.ParseSeverity(loglevel.Value())
	if !ok {
		log.Fatal("invalid log level, valid log levels: emergency, alert, critical, error, warn, notice, info, debug, trace")
	}

	certinject.SetLogLevel(level)
	logp.SetSeverity(level)

	var (
		b   []byte
		err error
	)

	cert := certflag.Value()
	if cert != "" {
		log.Debugf("reading certificate: %q", cert)

		b, err = ioutil.ReadFile(cert)
		if err != nil {
			log.Fatale(err, "error reading certificate")
		}

		certpem, _ := pem.Decode(b)
		if certpem != nil {
			log.Debugf("user provided PEM-encoded input file; checking type...")

			if certpem.Type != "CERTIFICATE" {
				log.Fatalf("PEM type was %s, expecting CERTIFICATE", certpem.Type)
			}

			log.Debugf("PEM file is a certificate; extracting DER bytes...")

			b = certpem.Bytes
		}
	}

	log.Debugf("injecting certificate...")

	certinject.InjectCert(b)
	log.Debugf("injected certificate: %q", cert)
}
