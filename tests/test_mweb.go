package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
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
	case 2:
		coin := &mweb.Coin{OutputId: &chainhash.Hash{}, SpendKey: &mw.SecretKey{}}
		inputKey := &mw.SecretKey{}
		binary.Read(r, binary.LittleEndian, coin.OutputId)
		binary.Read(r, binary.LittleEndian, coin.SpendKey)
		binary.Read(r, binary.LittleEndian, inputKey)
		input := mweb.CreateInput(coin, inputKey)
		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, input.Features)
		binary.Write(&buf, binary.LittleEndian, input.OutputId)
		binary.Write(&buf, binary.LittleEndian, input.InputPubKey)
		binary.Write(&buf, binary.LittleEndian, input.OutputPubKey)
		binary.Write(&buf, binary.LittleEndian, input.Signature)
		fmt.Println(hex.EncodeToString(buf.Bytes()))
	case 3:
		key := &mw.SecretKey{}
		msg := &chainhash.Hash{}
		binary.Read(r, binary.LittleEndian, key)
		binary.Read(r, binary.LittleEndian, msg)
		sig := mw.Sign(key, msg[:])
		fmt.Println(hex.EncodeToString(sig[:]))
	}
}
