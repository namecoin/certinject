// Copyright 2020 Namecoin Developers GPLv3+

// Command certinject injects certificates into all configured trust stores
package main

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/hlandau/xlog"
	"github.com/namecoin/certinject"
	easyconfig "gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var log, logp = xlog.New("certinject")

func main() {
	var (
		flagGroup = cflag.NewGroup(nil, "certinject")
		certflag  = cflag.String(flagGroup, "cert", "", "path to certificate to inject into trust store")
		loglevel  = cflag.String(flagGroup, "loglevel", "info", "logging level (from least to most verbose: emergency, alert, critical, error, warn, notice, info, debug, trace")
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
	certinject.Log.SetSeverity(level)
	logp.SetSeverity(level)

	cert := certflag.Value()
	if cert == "" {
		log.Fatal("no certificate to add")
	}
	log.Debugf("reading certificate: %q", cert)
	b, err := ioutil.ReadFile(cert)
	if err != nil {
		log.Fatale(err, "error reading certificate")
	}
	if p, err := pem.Decode(b); err == nil {
		log.Debugf("user provided PEM encoded certificate, extracting DER bytes")
		b = p.Bytes
	}
	certinject.InjectCert(b)
	log.Debugf("injected certificate: %q", cert)
}
