package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

func main() {
	b, _ := hex.DecodeString(os.Args[2])
	r := bytes.NewReader(b)
	switch n, _ := strconv.Atoi(os.Args[1]); n {
	case 1:
		coin := &mweb.Coin{SharedSecret: &mw.SecretKey{}}
		spendKey := &mw.SecretKey{}
		read(r, coin.SharedSecret, spendKey)
		coin.CalculateOutputKey(spendKey)
		fmt.Println(hex.EncodeToString(coin.SpendKey[:]))
	case 2:
		coin := &mweb.Coin{
			Blind:    &mw.BlindingFactor{},
			OutputId: &chainhash.Hash{},
			SpendKey: &mw.SecretKey{},
		}
		inputKey := &mw.SecretKey{}
		read(r, coin.Blind, &coin.Value, coin.OutputId, coin.SpendKey, inputKey)
		input := mweb.CreateInput(coin, inputKey)
		var buf bytes.Buffer
		write(&buf, input.Features, input.OutputId, input.Commitment,
			input.InputPubKey, input.OutputPubKey, input.Signature)
		fmt.Println(hex.EncodeToString(buf.Bytes()))
	case 3:
		key := &mw.SecretKey{}
		msg := &chainhash.Hash{}
		read(r, key, msg)
		sig := mw.Sign(key, msg[:])
		fmt.Println(hex.EncodeToString(sig[:]))
	case 4:
		key := &mw.SecretKey{}
		read(r, key)
		fmt.Println(hex.EncodeToString(key.PubKey()[:]))
	case 5:
		keychain := &mweb.Keychain{Scan: &mw.SecretKey{}, Spend: &mw.SecretKey{}}
		var index uint32
		read(r, keychain.Scan, keychain.Spend, &index)
		fmt.Println(hex.EncodeToString(keychain.SpendKey(index)[:]))
	case 6:
		keychain := &mweb.Keychain{Scan: &mw.SecretKey{}, Spend: &mw.SecretKey{}}
		var index uint32
		read(r, keychain.Scan, keychain.Spend, &index)
		addr := ltcutil.NewAddressMweb(keychain.Address(index), &chaincfg.MainNetParams)
		fmt.Println(hex.EncodeToString([]byte(addr.String())))
	case 7:
		kernelBlind := &mw.BlindingFactor{}
		stealthBlind := &mw.BlindingFactor{}
		read(r, kernelBlind, stealthBlind)
		kernel := mweb.CreateKernel(kernelBlind, stealthBlind, nil, nil, nil, nil)
		fmt.Println(hex.EncodeToString(kernel.Signature[:]))
	case 8:
		blind := &mw.BlindingFactor{}
		var value uint64
		read(r, blind, &value)
		commit := mw.NewCommitment(blind, value)
		var buf bytes.Buffer
		write(&buf, commit, commit.PubKey())
		fmt.Println(hex.EncodeToString(buf.Bytes()))
	case 9:
		blind := &mw.BlindingFactor{}
		var value uint64
		read(r, blind, &value)
		fmt.Println(hex.EncodeToString(mw.BlindSwitch(blind, value)[:]))
	case 10:
		recipient := &mweb.Recipient{}
		senderKey := &mw.SecretKey{}
		read(r, &recipient.Value)
		recipient.Address = &mw.StealthAddress{
			Scan: readPubkey(r), Spend: readPubkey(r),
		}
		read(r, senderKey)
		output, blind, shared := mweb.CreateOutput(recipient, senderKey)
		mweb.SignOutput(output, recipient.Value, blind, senderKey)
		var buf bytes.Buffer
		write(&buf, output.Commitment, output.SenderPubKey, output.ReceiverPubKey)
		output.Message.Serialize(&buf)
		write(&buf, blind, shared, output.RangeProofHash, output.Signature)
		fmt.Println(hex.EncodeToString(buf.Bytes()))
	case 12:
		keys := &mweb.Keychain{Scan: &mw.SecretKey{}, Spend: &mw.SecretKey{}}
		coin := &mweb.Coin{
			Blind:        &mw.BlindingFactor{},
			OutputId:     &chainhash.Hash{},
			SharedSecret: &mw.SecretKey{},
		}
		var addressIndex uint64
		recipient := &mweb.Recipient{}
		var fee, pegin uint64
		var nPegouts uint16
		var lockHeight uint32
		var pegouts []*wire.TxOut
		read(r, keys.Scan, keys.Spend, coin.Blind, &coin.Value,
			coin.OutputId, &addressIndex, coin.SharedSecret, &recipient.Value)
		recipient.Address = &mw.StealthAddress{
			Scan: readPubkey(r), Spend: readPubkey(r),
		}
		read(r, &fee, &pegin, &nPegouts, &lockHeight)
		for i := 0; i < int(nPegouts); i++ {
			var value int64
			var scriptLen byte
			read(r, &value, &scriptLen)
			pkScript := make([]byte, scriptLen)
			read(r, pkScript)
			pegouts = append(pegouts, wire.NewTxOut(value, pkScript))
		}
		coin.CalculateOutputKey(keys.SpendKey(uint32(addressIndex)))
		tx, newCoins, _ := mweb.NewTransaction([]*mweb.Coin{coin},
			[]*mweb.Recipient{recipient}, fee, pegin, pegouts,
			func(b []byte) error { copy(b, keys.Scan[:]); return nil }, nil)
		var buf bytes.Buffer
		input := tx.TxBody.Inputs[0]
		output := tx.TxBody.Outputs[0]
		kernel := tx.TxBody.Kernels[0]
		write(&buf, input.Features, input.OutputId, input.Commitment,
			input.InputPubKey, input.OutputPubKey, input.Signature,
			output.Commitment, output.SenderPubKey, output.ReceiverPubKey)
		output.Message.Serialize(&buf)
		write(&buf, newCoins[0].Blind, newCoins[0].SharedSecret,
			output.Signature, tx.KernelOffset, tx.StealthOffset,
			kernel.Features, kernel.Excess, kernel.StealthExcess,
			kernel.Signature, output.RangeProofHash)
		fmt.Println(hex.EncodeToString(buf.Bytes()))
	case 13:
		sa := &mw.StealthAddress{Scan: readPubkey(r), Spend: readPubkey(r)}
		addr := ltcutil.NewAddressMweb(sa, &chaincfg.MainNetParams)
		fmt.Println(hex.EncodeToString([]byte(addr.String())))
	}
}

func read(r io.Reader, xs ...any) {
	for _, x := range xs {
		binary.Read(r, binary.LittleEndian, x)
	}
}

func write(w io.Writer, xs ...any) {
	for _, x := range xs {
		binary.Write(w, binary.LittleEndian, x)
	}
}

func readPubkey(r io.Reader) *mw.PublicKey {
	var p [65]byte
	read(r, &p)
	P, _ := secp256k1.ParsePubKey(p[:])
	return (*mw.PublicKey)(P.SerializeCompressed())
}
