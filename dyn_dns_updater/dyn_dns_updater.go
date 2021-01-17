package main

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func realMain() error {
	// parse args
	pURL := flag.String("url", "", "the api")
	pName := flag.String("name", "", "the domain")
	pAddr := flag.String("addr", "", "the ip address")
	pTTL := flag.Uint("ttl", 10, "the TTL")
	flag.Parse()
	if *pURL == "" || *pName == "" || *pAddr == "" {
		return errors.New("missing params")
	}

	// open self as zip
	path, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "get self exe")
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		return errors.Wrap(err, "open self exe")
	}
	defer reader.Close()

	// read key and cert from zip
	var keyData []byte
	var certData []byte
	for _, file := range reader.File {
		if file.Name != "dnsproxy_client.crt" && file.Name != "dnsproxy_client.key" {
			continue
		}

		err := func() error {
			rc, err := file.Open()
			if err != nil {
				return errors.Wrap(err, "open zip file")
			}
			defer rc.Close()

			data, err := ioutil.ReadAll(rc)
			if err != nil {
				return errors.Wrap(err, "read zip file")
			}
			if file.Name == "dnsproxy_client.crt" {
				certData = data
			} else if file.Name == "dnsproxy_client.key" {
				keyData = data
			} else {
				panic("unreachable")
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	// parse cert and key
	if len(keyData) == 0 || len(certData) == 0 {
		return errors.New("cert or key not found")
	}
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return errors.Wrap(err, "tls.X509KeyPair")
	}

	// prepare http client
	trans := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	client := http.Client{
		Transport: trans,
		Timeout:   3 * time.Second,
	}

	// make request
	req := map[string]interface{}{}
	req["Name"] = *pName
	req["Addr"] = *pAddr
	req["TTL"] = *pTTL
	payload, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}

	resp, err := client.Post(*pURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return errors.Wrap(err, "post req")
	}

	// print response
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read response")
	}
	_, err = os.Stdout.Write(result)
	if err != nil {
		return errors.Wrap(err, "print response")
	}

	return nil
}

func main() {
	err := realMain()
	if err != nil {
		log.Fatal(err)
	}
}
