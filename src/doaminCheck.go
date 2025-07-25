package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"
)

// NetworkConnector is an interface to abstract network connections.
type NetworkConnector interface {
	Dial(network, address string) (net.Conn, error)
}

// RealNetworkConnector implements NetworkConnector using the real net.Dialer.
type RealNetworkConnector struct{}

func (rnc RealNetworkConnector) Dial(network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	return tls.DialWithDialer(dialer, network, address, tlsConfig)
}

func domainChecker(targetURL string) error {
	formattedURL := FormatURL(targetURL)
	conn, err := DialNetwork(formattedURL, RealNetworkConnector{})
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}
	defer conn.Close()

	expiryDate, err := GetCertificateExpiryDate(conn)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	remainingDays := CalculateRemainingDays(expiryDate)

	fmt.Printf("Expiry Date: %s Remaining Days: %d\n", expiryDate, remainingDays)

	return nil
}

// FormatURL formats the given URL to the desired format.
// If the URL starts with "https://", this function removes the prefix,
// trims any trailing "/" character, and appends ":443" to indicate the
// default HTTPS port. The formatted URL is returned as the result.
// for example https://example.com/ is going to return example.com:443
func FormatURL(targetURL string) string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Fatal(parsedURL)
	}
	if parsedURL.Scheme == "https" {
		targetURL = parsedURL.Host + ":443"
	}
	return targetURL
}

// DialNetwork uses the provided NetworkConnector to establish a network connection.
func DialNetwork(targetURL string, connector NetworkConnector) (net.Conn, error) {
	return connector.Dial("tcp", targetURL)
}

// GetCertificateExpiryDate retrieves the expiry date of the peer certificate.
func GetCertificateExpiryDate(conn net.Conn) (time.Time, error) {
	certChain := conn.(*tls.Conn).ConnectionState().PeerCertificates

	if len(certChain) == 0 {
		return time.Time{}, fmt.Errorf("no certificate found")
	}

	return certChain[0].NotAfter, nil
}

// CalculateRemainingDays calculates the remaining days until the given date.
func CalculateRemainingDays(expiryDate time.Time) int {
	return int(expiryDate.Sub(time.Now()).Hours() / 24)
}
