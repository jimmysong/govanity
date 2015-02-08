package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
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

	var numFound int
	var x, y *big.Int
	var zeros [32]byte
	var serialized [65]byte
	serialized[0] = 0x04 // Uncompressed pubkeys always start with 0x04.
	for {
		x, y = s256.ScalarBaseMult(seed)

		// Serialize the pubkey into uncompressed format.
		xBytes := x.Bytes()
		if len(xBytes) < 32 {
			bytesToZero := 32 - len(xBytes)
			copy(serialized[1:1+bytesToZero], zeros[:bytesToZero])
			copy(serialized[1+bytesToZero:], xBytes)
		} else {
			copy(serialized[1:], xBytes)
		}
		yBytes := y.Bytes()
		if len(yBytes) < 32 {
			bytesToZero := 32 - len(yBytes)
			copy(serialized[33:33+bytesToZero], zeros[:bytesToZero])
			copy(serialized[33+bytesToZero:], yBytes)
		} else {
			copy(serialized[33:], yBytes)
		}

		// Encode the address and check the prefix.
		addr := base58.CheckEncode(btcutil.Hash160(serialized[:]),
			net.PubKeyHashAddrID)
		if strings.HasPrefix(addr, prefix) {
			privkey, _ := btcec.PrivKeyFromBytes(s256, seed)
			wif, err := btcutil.NewWIF(privkey, net, false)
			if err != nil {
				fmt.Printf("failed to get wif: %s\n", err)
				os.Exit(1)
			}
			numFound++
			fmt.Printf("\nElapsed: %s\naddr: %s\nwif: %s\nnumfound: %d\n",
				time.Since(beginTime), addr, wif.String(),
				numFound)
		}

		seed[0]--
		for i := 0; seed[i] == 0; i++ {
			seed[i] = 255
			seed[i+1]--
		}
	}
}

func init() {
	// Panic on init if the assumptions used by the code change.
	if btcec.PubKeyBytesLenUncompressed != 65 {
		panic("Source code assumes 65-byte uncompressed secp256k1 " +
			"serialized public keys")
	}
}
