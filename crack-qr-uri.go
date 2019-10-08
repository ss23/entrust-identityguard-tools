package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
)

func main() {
	var uri = flag.String("uri", "", "Example: igmobileotp://?action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1&mac=mhVL8BWKaishMa5%2B")
	var threadsPtr = flag.Int("threads", 4, "Number of threads to use. Set to ncores, or ncores - 1. Load is 100% CPU")

	flag.Parse()

	threads := *threadsPtr

	if *uri == "" {
		panic("Specify a URI")
	}

	obj, err := url.Parse(*uri)
	if err != nil {
		panic(err)
	}

	if obj.Scheme != "igmobileotp" {
		fmt.Println("Only the scheme igmobileotp is currently supported")
	}

	// Parse the query string component
	q := obj.Query()

	if (len(q["action"]) != 1) || (q["action"][0] != "secactivate") {
		fmt.Println("Only the secactivate action is currently supported")
	}

	// Validate the encrypted data really exists
	if len(q["enc"]) != 1 {
		panic("No enc provided")
	}

	// Validate we have a MAC that we can verify decryption with
	if len(q["mac"]) != 1 {
		panic("No mac provided")
	}
	mac, err := base64.StdEncoding.DecodeString(q["mac"][0])
	if err != nil {
		panic(err)
	}

	// Decode the enc paramater
	enc, err := base64.StdEncoding.DecodeString(q["enc"][0])
	if err != nil {
		panic(err)
	}

	// Extract out the payload that is used for HMAC validation
	from := strings.Index(*uri, "?") + 1 // 1 more, because the ?
	to := strings.LastIndex(*uri, "&")
	hmacPayload := (*uri)[from:to]

	fmt.Println(hmacPayload)

	// Farm the work out to threads
	passwords := make(chan []byte)
	doner := make(chan bool, threads)

	for i := 0; i < threads; i++ {
		go checkPassword(enc[0:8], []byte(hmacPayload), mac, passwords, doner)
	}

	//for i := 54998317; i < 54998318; i++ {
	for i := 0; i < 99999999; i++ {
		passwords <- []byte(strconv.Itoa(i))
	}

	close(passwords)

	for i := 0; i < threads; i++ {
		<-doner
	}

	fmt.Println("Password was not found. Is your URI corrupted?")
	os.Exit(1)

}

func checkPassword(salt []byte, macedPayload []byte, macValue []byte, passwords <-chan []byte, doner chan<- bool) {
	for password := range passwords {
		dk := pbkdf2.Key(password, salt, 1000, 64, sha256.New)

		// Validate whether the key is correct with a HMAC verification
		hmacKey := dk[16:48]

		macer := hmac.New(sha256.New, hmacKey)
		macer.Write(macedPayload)
		calculatedMac := macer.Sum(nil)

		if reflect.DeepEqual(calculatedMac[0:12], macValue) {
			// Success!
			fmt.Println("Password found: ", string(password))
			os.Exit(0)
		}
	}

	doner <- true
}
