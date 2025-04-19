package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	// import CA certs
	_ "golang.org/x/crypto/x509roots/fallback"
)

func main() {
	var (
		url, fp string
		days    int
		verbose bool
	)
	flag.StringVar(&url, "u", "", "URL where the public key file is located")
	flag.StringVar(&fp, "f", "", "fingerprint to use to fetch file from keys.openpgp.org")
	flag.IntVar(&days, "d", 30, "Number of days into the future to check for expiry")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

	if url == "" && fp == "" {
		log.Fatal("Missing -u url or -f fingerprint parameter")
	}

	if url != "" && fp != "" {
		log.Fatal("Only one of -u or -f can be specified")
	}

	if fp != "" {
		url = fmt.Sprintf("https://keys.openpgp.org/vks/v1/by-fingerprint/%s", fp)
	}

	keydata, err := loadKey(url)
	if err != nil {
		log.Fatal(err)
	}

	key, err := crypto.NewKeyFromArmored(keydata)
	if err != nil {
		log.Fatal(err)
	}

	mytime := time.Now().AddDate(0, 0, days)

	e := key.GetEntity()
	selfsig, _ := e.PrimarySelfSignature()
	expired := checkPubKey(e.PrimaryKey, selfsig, mytime, verbose)
	for _, s := range e.Subkeys {
		if checkPubKey(s.PublicKey, s.Sig, mytime, verbose) {
			expired = true
		}
	}

	if expired {
		os.Exit(1)
	}
}

func loadKey(url string) (string, error) {
	buf := bytes.NewBuffer(nil)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func checkPubKey(p *packet.PublicKey, s *packet.Signature, t time.Time, verbose bool) bool {
	expiryTime, expires := getKeyExpiry(p, s)

	if !expires {
		if verbose {
			fmt.Printf("Key %s (%x) has no expiry date\n", p.KeyIdShortString(), p.Fingerprint)
		}
		return false
	}

	if t.Unix() < p.CreationTime.Unix() {
		fmt.Printf("Key %s (%x) is only valid after %s\n", p.KeyIdShortString(), p.Fingerprint, s.CreationTime.Format("2006-01-02"))
		return true
	}

	if t.Unix() > expiryTime.Unix() {
		fmt.Printf("Key %s (%x) is not valid after %s\n", p.KeyIdShortString(), p.Fingerprint, expiryTime.Format("2006-01-02"))
		return true
	}

	if verbose {
		fmt.Printf("Key %s (%x) expires on %s\n", p.KeyIdShortString(), p.Fingerprint, expiryTime.Format("2006-01-02"))
	}
	return false
}

func getKeyExpiry(p *packet.PublicKey, s *packet.Signature) (time.Time, bool) {
	if s.KeyLifetimeSecs == nil || *s.KeyLifetimeSecs == 0 {
		return time.Time{}, false
	}
	return p.CreationTime.Add(time.Duration(*s.KeyLifetimeSecs) * time.Second), true
}
