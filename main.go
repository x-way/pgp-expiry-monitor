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
)

func main() {
	url := flag.String("u", "", "URL where the public key file is located")
	days := flag.Int("d", 30, "Number of days into the future to check for expiry")
	flag.Parse()

	if *url == "" {
		log.Fatal("Missing -u url parameter")
	}

	keydata, err := loadKey(*url)
	if err != nil {
		log.Fatal(err)
	}

	key, err := crypto.NewKeyFromArmored(keydata)
	if err != nil {
		log.Fatal(err)
	}

	mytime := time.Now().AddDate(0, 0, *days)

	e := key.GetEntity()
	selfsig, _ := e.PrimarySelfSignature()
	expired := checkPubKey(e.PrimaryKey, selfsig, mytime)
	for _, s := range e.Subkeys {
		if checkPubKey(s.PublicKey, s.Sig, mytime) {
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

func checkPubKey(p *packet.PublicKey, s *packet.Signature, t time.Time) bool {
	if expiredKey(s, t) {
		fmt.Printf("Key %s (%x) is not valid on %s\n", p.KeyIdShortString(), p.Fingerprint, t.Format("01.02.2006"))
		return true
	}

	return false
}

func expiredKey(s *packet.Signature, t time.Time) bool {
	if t.Unix() < s.CreationTime.Unix() {
		return true
	}
	if s.KeyLifetimeSecs == nil || *s.KeyLifetimeSecs == 0 {
		return false
	}
	expiry := s.CreationTime.Add(time.Duration(*s.KeyLifetimeSecs) * time.Second)
	return t.Unix() > expiry.Unix()
}
