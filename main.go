package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

func retrievePubKeyFilePaths(dir string, subdirskip string) []string {
	list := make([]string, 0)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// fmt.Printf("Error accessing path %q, %v\n", dir, err)
			return err
		}
		if info.IsDir() && info.Name() == subdirskip {
			// fmt.Printf("Skipping dir %+v\n", info.Name())
			return filepath.SkipDir
		}
		if info.Name()[len(info.Name())-3:len(info.Name())] == "pem" {
			// fmt.Printf("Found a PEM! %v\n", info.Name())
			list = append(list, path)
		}
		// fmt.Printf("Visited path %q\n", path)
		return nil
	})
	if err != nil {
		fmt.Printf("Error walking through path %q: %v\n", dir, err)
	}
	return list
}

func createPubKeys(filepaths []string) ([]*rsa.PublicKey, error) {
	pubKeys := make([]*rsa.PublicKey, 0)
	for i := range filepaths {
		println("FILE: ", filepaths[i])
		dat, err := ioutil.ReadFile(filepaths[i])
		if err != nil {
			fmt.Printf("Error reading file %v %v\n", filepaths[i], err)
			return nil, err
		}
		block, rest := pem.Decode(dat)
		if rest == nil {
			fmt.Printf("File: %v is not a valid PEM file", filepaths[i])
			return nil, err
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			fmt.Printf("Error parsing file as public key: %v %v", filepaths[i], err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if ok {
			pubKeys = append(pubKeys, rsaPub)
		}
	}
	return pubKeys, nil
}

func main() {
	filepaths := retrievePubKeyFilePaths("res", "sample")
	pubKeys, err := createPubKeys(filepaths)
	if err != nil {
		log.Fatal("Error reading files due to error: ", err)
	}

	//i and j are the index of the pair of the pub key generated
	for i := range pubKeys {
		for j := i + 1; j < len(pubKeys); j++ {
			hcf := big.NewInt(0)
			hcf.GCD(nil, nil, pubKeys[i].N, pubKeys[j].N)
			if hcf != big.NewInt(1) {
				fmt.Printf("Key: %v has common factor with Key: %v", pubKeys[i], pubKeys[j])
			}
		}
	}
}
