package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

func main() {
	beginTime := time.Now()

	var prefix string
	flag.StringVar(&prefix, "prefix", "123", "prefix you want for your vanity address")
	flag.Parse()

	fmt.Printf("Searching for prefix \"%s\"\n", prefix)

	s256 := btcec.S256()
	net := &chaincfg.MainNetParams

	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		fmt.Printf("failed to read seed data: %s\n", err)
		os.Exit(1)
	}

	pubkey := btcec.PublicKey{}
	pubkey.Curve = s256

	for {
		pubkey.X, pubkey.Y = s256.ScalarBaseMult(seed)

		addr1, err := btcutil.NewAddressPubKey(pubkey.SerializeUncompressed(), net)

		if err != nil {
			fmt.Printf("failed to get pubkey: %s\n", err)
			os.Exit(1)
		}

		str1 := addr1.EncodeAddress()
		if strings.HasPrefix(str1, prefix) {
			privkey, _ := btcec.PrivKeyFromBytes(s256, seed)
			wif, err := btcutil.NewWIF(privkey, net, false)
			if err != nil {
				fmt.Printf("failed to get wif: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nElapsed: %s\naddr: %s\nwif: %s\n", time.Since(beginTime), str1, wif.String())
		}

		seed[0]--
		for i := 0; seed[i] == 0; i++ {
			seed[i] = 255
			seed[i+1]--
		}
	}
}
