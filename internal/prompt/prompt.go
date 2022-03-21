package prompt

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abesalrs"
	"github.com/abesuite/abec/abeutil/hdkeychain"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/internal/legacy/keystore"
	"github.com/abesuite/abewallet/wordlists"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"strconv"
	"strings"
)

// ProvideSeed is used to prompt for the wallet seed which maybe required during
// upgrades.
func ProvideSeed() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter existing wallet seed: ")
		seedStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		seedStr = strings.TrimSpace(strings.ToLower(seedStr))

		seed, err := hex.DecodeString(seedStr)
		if err != nil || len(seed) < hdkeychain.MinSeedBytes ||
			len(seed) > hdkeychain.MaxSeedBytes {

			fmt.Printf("Invalid seed specified.  Must be a "+
				"hexadecimal value that is at least %d bits and "+
				"at most %d bits\n", hdkeychain.MinSeedBytes*8,
				hdkeychain.MaxSeedBytes*8)
			continue
		}

		return seed, nil
	}
}

// ProvidePrivPassphrase is used to prompt for the private passphrase which
// maybe required during upgrades.
func ProvidePrivPassphrase() ([]byte, error) {
	prompt := "Enter the private passphrase of your wallet: "
	for {
		fmt.Print(prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		return pass, nil
	}
}

// promptList prompts the user with the given prefix, list of valid responses,
// and default list entry to use.  The function will repeat the prompt to the
// user until they enter a valid response.
func promptList(reader *bufio.Reader, prefix string, validResponses []string, defaultEntry string) (string, error) {
	// Setup the prompt according to the parameters.
	validStrings := strings.Join(validResponses, "/")
	var prompt string
	if defaultEntry != "" {
		prompt = fmt.Sprintf("%s (%s) [%s]: ", prefix, validStrings,
			defaultEntry)
	} else {
		prompt = fmt.Sprintf("%s (%s): ", prefix, validStrings)
	}

	// Prompt the user until one of the valid responses is given.
	for {
		fmt.Print(prompt)
		reply, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		reply = strings.TrimSpace(strings.ToLower(reply))
		if reply == "" {
			reply = defaultEntry
		}

		for _, validResponse := range validResponses {
			if reply == validResponse {
				return reply, nil
			}
		}
	}
}

// promptListBool prompts the user for a boolean (yes/no) with the given prefix.
// The function will repeat the prompt to the user until they enter a valid
// reponse.
func promptListBool(reader *bufio.Reader, prefix string, defaultEntry string) (bool, error) {
	// Setup the valid responses.
	valid := []string{"n", "no", "y", "yes"}
	response, err := promptList(reader, prefix, valid, defaultEntry)
	if err != nil {
		return false, err
	}
	return response == "yes" || response == "y", nil
}

// promptPass prompts the user for a passphrase with the given prefix.  The
// function will ask the user to confirm the passphrase and will repeat the
// prompts until they enter a matching response.
func promptPass(reader *bufio.Reader, prefix string, confirm bool) ([]byte, error) {
	// Prompt the user until they enter a passphrase.
	prompt := fmt.Sprintf("%s: ", prefix)
	for {
		fmt.Print(prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		if !confirm {
			return pass, nil
		}

		fmt.Print("Confirm passphrase: ")
		confirm, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		confirm = bytes.TrimSpace(confirm)
		if !bytes.Equal(pass, confirm) {
			fmt.Println("The entered passphrases do not match")
			continue
		}

		return pass, nil
	}
}

// PrivatePass prompts the user for a private passphrase with varying behavior
// depending on whether the passed legacy keystore exists.  When it does, the
// user is prompted for the existing passphrase which is then used to unlock it.
// On the other hand, when the legacy keystore is nil, the user is prompted for
// a new private passphrase.  All prompts are repeated until the user enters a
// valid response.
func PrivatePass(reader *bufio.Reader, legacyKeyStore *keystore.Store) ([]byte, error) {
	// When there is not an existing legacy wallet, simply prompt the user
	// for a new private passphase and return it.
	if legacyKeyStore == nil {
		return promptPass(reader, "Enter the private "+
			"passphrase for your new wallet", true)
	}

	// At this point, there is an existing legacy wallet, so prompt the user
	// for the existing private passphrase and ensure it properly unlocks
	// the legacy wallet so all of the addresses can later be imported.
	fmt.Println("You have an existing legacy wallet.  All addresses from " +
		"your existing legacy wallet will be imported into the new " +
		"wallet format.")
	for {
		privPass, err := promptPass(reader, "Enter the private "+
			"passphrase for your existing wallet", false)
		if err != nil {
			return nil, err
		}

		// Keep prompting the user until the passphrase is correct.
		if err := legacyKeyStore.Unlock([]byte(privPass)); err != nil {
			if err == keystore.ErrWrongPassphrase {
				fmt.Println(err)
				continue
			}

			return nil, err
		}

		return privPass, nil
	}
}

// PublicPass prompts the user whether they want to add an additional layer of
// encryption to the wallet.  When the user answers yes and there is already a
// public passphrase provided via the passed config, it prompts them whether or
// not to use that configured passphrase.  It will also detect when the same
// passphrase is used for the private and public passphrase and prompt the user
// if they are sure they want to use the same passphrase for both.  Finally, all
// prompts are repeated until the user enters a valid response.
func PublicPass(reader *bufio.Reader, privPass []byte,
	defaultPubPassphrase, configPubPassphrase []byte) ([]byte, error) {

	pubPass := defaultPubPassphrase
	usePubPass, err := promptListBool(reader, "Do you want "+
		"to add an additional layer of encryption for public "+
		"data?", "no")
	if err != nil {
		return nil, err
	}

	if !usePubPass {
		return pubPass, nil
	}

	if !bytes.Equal(configPubPassphrase, pubPass) {
		useExisting, err := promptListBool(reader, "Use the "+
			"existing configured public passphrase for encryption "+
			"of public data?", "no")
		if err != nil {
			return nil, err
		}

		if useExisting {
			return configPubPassphrase, nil
		}
	}

	for {
		pubPass, err = promptPass(reader, "Enter the public "+
			"passphrase for your new wallet", true)
		if err != nil {
			return nil, err
		}

		if bytes.Equal(pubPass, privPass) {
			useSamePass, err := promptListBool(reader,
				"Are you sure want to use the same passphrase "+
					"for public and private data?", "no")
			if err != nil {
				return nil, err
			}

			if useSamePass {
				break
			}

			continue
		}

		break
	}

	fmt.Println("NOTE: Use the --walletpass option to configure your " +
		"public passphrase.")
	return pubPass, nil
}

// Seed prompts the user whether they want to use an existing wallet generation
// seed.  When the user answers no, a seed will be generated and displayed to
// the user along with prompting them for confirmation.  When the user answers
// yes, a the user is prompted for it.  All prompts are repeated until the user
// enters a valid response.
func Seed(reader *bufio.Reader) ([]byte, error) {
	// Ascertain the wallet generation seed.
	useUserSeed, err := promptListBool(reader, "Do you have an "+
		"existing wallet seed you want to use?", "no")
	if err != nil {
		return nil, err
	}
	if !useUserSeed {
		//seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		//seed, err := abesalrs.GenerateSeed(2*abesalrs.RecommendedSeedLen)
		// TODO(20220321): the length of seed should be a global parameter in config
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		if err != nil {
			return nil, errors.New("rand.Read() error in Seed()")
		}
		mnemonics := seedToWords(seed, wordlists.English)
		fmt.Println("Your wallet generation seed is:")
		fmt.Printf("%x\n", seed)
		fmt.Println("the crypto version is", binary.BigEndian.Uint32(seed[:4]))
		fmt.Println("Your wallet mnemonic list is:")
		fmt.Printf("%v\n", strings.Join(mnemonics, ","))
		fmt.Println("IMPORTANT: Keep the version and seed in a safe place as you\n" +
			"will NOT be able to restore your wallet without it.")
		fmt.Println("Please keep in mind that anyone who has access\n" +
			"to the seed can also restore your wallet thereby\n" +
			"giving them access to all your funds, so it is\n" +
			"imperative that you keep it in a secure location.")

		for {
			fmt.Print(`Once you have stored the seed in a safe ` +
				`and secure location, enter "OK" to continue: `)
			confirmSeed, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			confirmSeed = strings.TrimSpace(confirmSeed)
			confirmSeed = strings.Trim(confirmSeed, `"`)
			if confirmSeed == "OK" {
				break
			}
		}
		return seed, nil
	}

	for {
		fmt.Print("Enter the crypto version is:")
		versionStr, err := reader.ReadString('\n')
		versionStr = strings.TrimSpace(strings.ToLower(versionStr))
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			return nil, err
		}
		fmt.Print("Enter existing wallet mnemonic: ")
		seedStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		seedStr = strings.TrimSpace(strings.ToLower(seedStr))
		mnemonics := strings.Split(seedStr, ",")
		seed := wordsToSeed(mnemonics, wordlists.EnglishMap)
		if len(seed) != 33 {
			fmt.Printf("Invalid mnemonic word list specified\n")
			continue
		}
		seedH := chainhash.DoubleHashH(seed[:32])
		if !bytes.Equal(seedH[:1], seed[32:]) {
			fmt.Printf("Invalid mnemonic word list specified\n")
			continue
		}
		seed = seed[:32]
		//seed, err := hex.DecodeString(seedStr)
		//TODO(abe20210801):remove the salrs dependency
		if err != nil || len(seed) < abesalrs.MinSeedBytes ||
			len(seed) > abesalrs.MaxSeedBytes {
			//if err != nil || len(seed) < hdkeychain.MinSeedBytes ||
			//	len(seed) > hdkeychain.MaxSeedBytes {
			fmt.Printf("Invalid mnemonic word list specified\n")
			//fmt.Printf("Invalid seed specified.  Must be a "+
			//	"hexadecimal value that is at least %d bits and "+
			//	"at most %d bits\n", hdkeychain.MinSeedBytes*8,
			//	hdkeychain.MaxSeedBytes*8)
			continue
		}
		// add the cryptoScheme before seed
		tmp := make([]byte, 4, 4+32)
		binary.BigEndian.PutUint32(tmp[0:4], uint32(version))
		seed = append(tmp, seed[:]...)
		return seed, nil
	}
}

func SeedToWords(seed []byte, wordlist []string) []string {
	return seedToWords(seed, wordlist)
}

func seedToWords(seed []byte, wordlist []string) []string {
	res := make([]string, 0, 24)
	hash := chainhash.DoubleHashH(seed)
	tmp := make([]byte, len(seed)+1)
	copy(tmp, seed)
	copy(tmp[len(seed):], hash[:1])
	// 11-bit
	pos := 0
	index := -1
	for pos < len(tmp) {
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
	return res
}

func WordsToSeed(words []string, wordMap map[string]int) []byte {
	return wordsToSeed(words, wordMap)
}

func wordsToSeed(words []string, wordMap map[string]int) []byte {
	res := make([]byte, 0, 33)
	indexs := make([]int, len(words))
	for i := 0; i < len(words); i++ {
		trim_word := strings.TrimSpace(words[i])
		indexs[i] = wordMap[trim_word]
	}
	pos := 0
	for pos < len(indexs) {
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
	return res
}
