package prompt

import (
	"bytes"
	"errors"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/tyler-smith/go-bip39"
	"strings"
)

const MnemonicNum = 24

func NewEntropy(length int) ([]byte, error) {
	return bip39.NewEntropy(length * 8)
}

// EntropyToWords convert entropy to mnemonic list
// abecryptoxparam.CryptoSchemePQRingCT: mnemonic list <-> entropy <-> seed
// abecryptoxparam.CryptoSchemePQRingCTX: entropy <-> mnemonic list -> seed
func EntropyToWords(cryptoScheme abecryptoxparam.CryptoScheme, entropy []byte, wordlist []string) ([]string, error) {
	if cryptoScheme != abecryptoxparam.CryptoSchemePQRingCT && cryptoScheme != abecryptoxparam.CryptoSchemePQRingCTX {
		return nil, errors.New("unsupported crypto scheme")
	}
	if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCT {
		return seedToWords(entropy, wordlist)
	}

	mnemonics, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}
	return strings.Split(mnemonics, " "), nil
}

func WordsToEntropy(cryptoScheme abecryptoxparam.CryptoScheme, mnemonics []string, wordMap map[string]int) ([]byte, error) {
	if cryptoScheme != abecryptoxparam.CryptoSchemePQRingCT && cryptoScheme != abecryptoxparam.CryptoSchemePQRingCTX {
		return nil, errors.New("unsupported crypto scheme")
	}
	if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCT {
		return wordsToSeed(mnemonics, wordMap)
	}
	if valid := bip39.IsMnemonicValid(strings.Join(mnemonics, " ")); !valid {
		return nil, errors.New("invalid mnemonic list")
	}
	entropy, err := bip39.EntropyFromMnemonic(strings.Join(mnemonics, " "))
	if err != nil {
		return nil, err
	}
	return entropy, nil
}

// SeedToWords
// abecryptoxparam.CryptoSchemePQRingCT: mnemonic list <-> entropy <-> seed
// abecryptoxparam.CryptoSchemePQRingCTX: entropy <-> mnemonic list -> seed
func SeedToWords(cryptoScheme abecryptoxparam.CryptoScheme, seed []byte, wordlist []string) ([]string, error) {
	if cryptoScheme != abecryptoxparam.CryptoSchemePQRingCT && cryptoScheme != abecryptoxparam.CryptoSchemePQRingCTX {
		return nil, errors.New("unsupported crypto scheme")
	}
	if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCT {
		return seedToWords(seed, wordlist)
	}
	return nil, errors.New("unsupported conversion")
}

func seedToWords(seed []byte, wordlist []string) ([]string, error) {
	res := make([]string, 0, MnemonicNum)
	hash := chainhash.DoubleHashH(seed)
	tmp := make([]byte, len(seed)+1)
	copy(tmp, seed)
	copy(tmp[len(seed):], hash[:1])
	// 11-bit
	pos := 0
	index := -1
	for pos < len(tmp) {
		if pos+10 >= len(tmp) {
			return nil, errors.New("invalid seed")
		}
		// 8 + 3
		index = int(tmp[pos]<<0)<<3 | int(tmp[pos+1]>>5)
		res = append(res, wordlist[index])
		// 5 + 6
		index = int(tmp[pos+1]&0x1F)<<6 | int(tmp[pos+2]>>2)
		res = append(res, wordlist[index])
		// 2 + 8 + 1
		index = int(tmp[pos+2]&0x3)<<9 | int(tmp[pos+3])<<1 | int(tmp[pos+4]>>7)
		res = append(res, wordlist[index])
		// 7 + 4
		index = int(tmp[pos+4]&0x7F)<<4 | int(tmp[pos+5]>>4)
		res = append(res, wordlist[index])
		// 4 + 7
		index = int(tmp[pos+5]&0xF)<<7 | int(tmp[pos+6]>>1)
		res = append(res, wordlist[index])
		// 1 + 8 + 2
		index = int(tmp[pos+6]&0x1)<<10 | int(tmp[pos+7])<<2 | int(tmp[pos+8]>>6)
		res = append(res, wordlist[index])
		// 6 + 5
		index = int(tmp[pos+8]&0x3F)<<5 | int(tmp[pos+9]>>3)
		res = append(res, wordlist[index])
		// 3 + 8
		index = int(tmp[pos+9]&0x7)<<8 | +int(tmp[pos+10]>>0)
		res = append(res, wordlist[index])
		pos += 11
	}
	return res, nil
}

// WordsToSeed convert mnemonic list to seed
// abecryptoxparam.CryptoSchemePQRingCT: mnemonic list <-> entropy <-> seed
// abecryptoxparam.CryptoSchemePQRingCTX: entropy <-> mnemonic list -> seed
func WordsToSeed(cryptoScheme abecryptoxparam.CryptoScheme, words []string, wordMap map[string]int) ([]byte, error) {
	if cryptoScheme != abecryptoxparam.CryptoSchemePQRingCT && cryptoScheme != abecryptoxparam.CryptoSchemePQRingCTX {
		return nil, errors.New("unsupported crypto scheme")
	}
	if len(words) != MnemonicNum {
		return nil, errors.New("invalid mnemonic list")
	}

	if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCT {
		return wordsToSeed(words, wordMap)
	}

	if valid := bip39.IsMnemonicValid(strings.Join(words, " ")); !valid {
		return nil, errors.New("invalid mnemonic list")
	}
	return bip39.NewSeed(strings.Join(words, " "), ""), nil
}

func wordsToSeed(words []string, wordMap map[string]int) ([]byte, error) {
	res := make([]byte, 0, SeedLength+1)
	indexs := make([]int, len(words))
	for i := 0; i < len(words); i++ {
		trim_word := strings.TrimSpace(words[i])
		indexs[i] = wordMap[trim_word]
	}
	pos := 0
	for pos < len(indexs) {
		if pos+7 >= len(indexs) {
			return nil, errors.New("invalid mnemonic list")
		}
		res = append(res, byte((indexs[pos+0]&0x7F8)>>3))                                // high 8
		res = append(res, byte((indexs[pos+0]&0x7)<<5)|byte((indexs[pos+1]&0x7C0)>>6))   // low 3 <<5 || high 5 >> 6
		res = append(res, byte((indexs[pos+1]&0x3F)<<2)|byte((indexs[pos+2]&0x600)>>9))  // low 6 << 2 || high 2 >>9
		res = append(res, byte((indexs[pos+2]&0x1FE)>>1))                                // mid 8 >> 1
		res = append(res, byte((indexs[pos+2]&0x1)<<7)|byte((indexs[pos+3]&0x7F0)>>4))   // low 1 << 7 || high 7 >> 4
		res = append(res, byte((indexs[pos+3]&0xF)<<4)|byte((indexs[pos+4]&0x780)>>7))   // low 4 << 4 || high 4 >> 7
		res = append(res, byte((indexs[pos+4]&0x7F)<<1)|byte((indexs[pos+5]&0x400)>>10)) // low 7  << 1 || high 1 >> 10
		res = append(res, byte((indexs[pos+5]&0x3FC)>>2))                                // mid 8 >> 2
		res = append(res, byte((indexs[pos+5]&0x3)<<6)|byte((indexs[pos+6]&0x7E0)>>5))   // low 2  << 6 || high 6 >> 5
		res = append(res, byte((indexs[pos+6]&0x1F)<<3)|byte((indexs[pos+7]&0x700)>>8))  // low 5  << 3 || high 3 >> 8
		res = append(res, byte((indexs[pos+7]&0xFF)>>0))                                 // low 8
		pos += 8
	}

	if len(res) != SeedLength+1 {
		return nil, errors.New("Invalid mnemonic word list specified\n")
	}
	seedH := chainhash.DoubleHashH(res[:SeedLength])
	if !bytes.Equal(seedH[:1], res[SeedLength:]) {
		return nil, errors.New("Invalid mnemonic word list specified")
	}

	return res[:SeedLength], nil
}
