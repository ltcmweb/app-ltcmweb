package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

func main() {
	b, _ := hex.DecodeString(os.Args[2])
	r := bytes.NewReader(b)
	switch n, _ := strconv.Atoi(os.Args[1]); n {
	case 1:
		coin := &mweb.Coin{SharedSecret: &mw.SecretKey{}}
		spendKey := &mw.SecretKey{}
		binary.Read(r, binary.LittleEndian, coin.SharedSecret)
		binary.Read(r, binary.LittleEndian, spendKey)
		coin.CalculateOutputKey(spendKey)
		fmt.Println(hex.EncodeToString(coin.SpendKey[:]))
	}
}
