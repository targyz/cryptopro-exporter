//MIT License
//
//Copyright (c) 2020 targyz
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

package main

import (
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"os"
	"time"
)

var addr = flag.String("listen-address", `:9189`, "The address to listen on for HTTP requests.")
var cpconfig = flag.String("cpconfig", `/opt/cprocsp/sbin/amd64/cpconfig`, "cpconfig bin, default /opt/cprocsp/sbin/amd64/cpconfig")
var certmgr = flag.String("certmgr", `/opt/cprocsp/bin/amd64/certmgr`, "certmgr bin, default /opt/cprocsp/bin/amd64/certmgr")
var period = flag.Int("period", 720, "How often to check in minutes, default 720 (12 hours)")
var cryptcp = flag.String("cryptcp", `/opt/cprocsp/bin/amd64/cryptcp`, "cpconfig bin, default /opt/cprocsp/bin/amd64/cryptcp")
var ensure = flag.Bool("ensure", false, "Run checks and print metric values")

func main() {

	flag.Parse()

	mgr := CPMgr{
		Cpconfig: *cpconfig,
		Certmgr:  *certmgr,
		Cryptcp:  *cryptcp,
	}

	if *ensure {
		runChecksAndExit(mgr)
	}

	cryptoVersion := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cryptopro_version",
			Help: "Current cryptopro version",
		})
	licenseActive := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cryptopro_license_active",
			Help: "Shows if licence permanent or not",
		})
	licensePermanent := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cryptopro_license_permanent",
			Help: "Shows if licence permanent or not",
		})
	licenseExpiresIn := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cryptopro_license_expires_in",
			Help: "Days before license expiry",
		})
	userCertificateExpiresIn := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cryptopro_user_certificate_expires_in",
			Help: "Days before user certificate expire",
		}, []string{"container"})

	errorsTotal := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cryptopro_exporter_errors_total",
			Help: "Total errors during runtime. Check logs if value is greater than 0",
		})
	errorsLicense := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cryptopro_exporter_errors_license",
			Help: "Errors count. Check logs if value is greater than 0",
		})
	errorsUserCertificates := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cryptopro_exporter_errors_user_certificates",
			Help: "Total error count  in runtime. Check logs if value is greater than 0",
		})
	errorsVersion := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cryptopro_exporter_errors_version",
			Help: "Total error count  in runtime. Check logs if value is greater than 0",
		})
	prometheus.MustRegister(cryptoVersion)
	prometheus.MustRegister(licenseActive)
	prometheus.MustRegister(licensePermanent)
	prometheus.MustRegister(licenseExpiresIn)
	prometheus.MustRegister(userCertificateExpiresIn)
	prometheus.MustRegister(errorsLicense)
	prometheus.MustRegister(errorsUserCertificates)
	prometheus.MustRegister(errorsTotal)
	prometheus.MustRegister(errorsVersion)

	go func() {
		for {
			// reset gauges
			licensePermanent.Set(0)
			licenseActive.Set(0)
			licenseExpiresIn.Set(0)

			permanent, active, days, err := mgr.getLicenseInfo()

			if err != nil {
				log.Printf("license check finished with error: %v", err)
				errorsVersion.Inc()
				errorsTotal.Inc()
			} else {
				licensePermanent.Set(boolToFloat64(permanent))
				licenseActive.Set(boolToFloat64(active))
				licenseExpiresIn.Set(float64(days))
			}
			time.Sleep(time.Minute * time.Duration(*period))
		}
	}()

	go func() {
		for {
			// reset gauges
			cryptoVersion.Set(0)

			version, err := mgr.getVersion()

			if err != nil {
				log.Printf("version check finished with error: %v", err)
				errorsVersion.Inc()
				errorsTotal.Inc()
			} else {
				cryptoVersion.Set(version)
			}
			time.Sleep(time.Minute * time.Duration(*period))
		}
	}()

	go func() {
		for {

			// TODO проверить корректность работы метода Reset и сброс метрик
			userCertificateExpiresIn.Reset()
			certNames, expireIn, err := mgr.GetUserCertsInfo()
			if err != nil {
				log.Printf("user certificates check finished with error: %v", err)
				errorsTotal.Inc()
				errorsUserCertificates.Inc()
			}
			for i, n := range certNames {
				userCertificateExpiresIn.WithLabelValues(n).Set(expireIn[i])
			}
			time.Sleep(time.Minute * time.Duration(*period))
		}
	}()

	http.Handle("/metrics", promhttp.Handler())

	log.Printf("Starting web server at %s\n", *addr)
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Printf("http.ListenAndServe: %v\n", err)
	}
}

func runChecksAndExit(mgr CPMgr) {
	version, err := mgr.getVersion()
	if err != nil {
		fmt.Printf(`An error occured while running version check: %v`, err)
		os.Exit(1)
	}
	fmt.Printf("Version: %v\n\n", version)

	permanent, active, days, err := mgr.getLicenseInfo()

	if err != nil {
		fmt.Printf(`An error occured while running license check: %v`, err)
		os.Exit(1)
	}
	fmt.Printf("Licence is active: %v\n", active)
	fmt.Printf("Licence is permanent: %v\n", permanent)
	fmt.Printf("Licence expires in %v days\n", days)

	certNames, expireIn, err := mgr.GetUserCertsInfo()
	if err != nil {
		fmt.Printf(`An error occured while running user certificates check: %v\n`, err)
		os.Exit(1)
	}

	fmt.Println("")

	for i, n := range certNames {
		fmt.Printf("Certificate %v expires in %v days\n", n, expireIn[i])
	}
	fmt.Println("")
	os.Exit(0)
}
