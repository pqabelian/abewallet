package prompt

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/abeutil/hdkeychain"
	"github.com/abesuite/abewallet/wordlists"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"strconv"
	"strings"
)

const SeedLength = 32
const MAXCOUNTERADDRESS = 0xFFFF_FFFF_FFFF_FFFF

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
func promptPass(_ *bufio.Reader, prefix string, confirm bool) ([]byte, error) {
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
func PrivatePass(reader *bufio.Reader) ([]byte, error) {
	return promptPass(reader, "Enter the private "+
		"passphrase for your new wallet", true)
}

// PublicPass prompts the user whether they want to add an additional layer of
// encryption to the wallet.  When the user answers yes and there is already a
// public passphrase provided via the passed config, it prompts them whether or
// not to use that configured passphrase.  It will also detect when the same
// passphrase is used for the private and public passphrase and prompt the user
// if they are sure they want to use the same passphrase for both.  Finally, all
// prompts are repeated until the user enters a valid response.
func PublicPass(reader *bufio.Reader, privPass []byte,
	configPubPassphrase []byte) ([]byte, error) {
	if len(configPubPassphrase) != 0 {
		useExisting, err := promptListBool(reader, "Use the "+
			"existing configured public passphrase for encryption "+
			"of non-private data?", "no")
		if err != nil {
			return nil, err
		}

		if useExisting {
			return configPubPassphrase, nil
		}
	}
	var pubPass []byte
	var err error
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

// PrivacyLevel prompts the user enter their privacy preferences, This determines
// the type of all addresses generated by the wallet.
func PrivacyLevel(reader *bufio.Reader, scheme abecryptoxparam.CryptoScheme) (abecryptoxkey.PrivacyLevel, error) {
	if scheme == abecryptoxparam.CryptoSchemePQRingCT {
		return abecryptoxkey.PrivacyLevelRINGCTPre, nil
	}

	// For CryptoScheme abecryptoxparam.CryptoSchemePQRingCTX(1),
	// PrivacyLevel:
	//abecryptoxkey.PrivacyLevelRINGCTPre(0) [can not be chosen]
	// abecryptoxkey.PrivacyLevelRINGCT(1)
	// abecryptoxkey.PrivacyLevelPSEUDONYM(2)

	// Setup the valid responses.
	valid := []string{"1", "2"}
	defaultEntry := "1" //   abecryptoxkey.PrivacyLevelPSEUDONYM
	response, err := promptList(reader, "Please choose "+
		"privacy level for future usage of the wallet[1:Full-Privacy,2:Pseudonym]:",
		valid, defaultEntry)
	if err != nil {
		return 0, err
	}
	return abecryptoxkey.PrivacyLevel(response[0] - '0'), nil
}

// Seed prompts the user whether they want to use an existing wallet generation
// seed.  When the user answers no, a seed will be generated and displayed to
// the user along with prompting them for confirmation.  When the user answers
// yes, a the user is prompted for it.  All prompts are repeated until the user
// enters a valid response.
func Seed(reader *bufio.Reader) (abecryptoxparam.CryptoScheme, abecryptoxkey.PrivacyLevel, []byte, uint64, error) {
	// Ascertain the wallet generation seed.
	useUserSeed, err := promptListBool(reader, "Do you have an "+
		"existing wallet seed you want to use?", "no")
	if err != nil {
		return 0, 0, nil, 0, err
	}

	// When user do not have any seed, generate one and use the latest crypto scheme as default
	// meanwhile ask user to choose the privacy level
	// currently 1 for Full-Privacy and 2 for Pseudonym
	if !useUserSeed {
		//seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		//seed, err := abesalrs.GenerateSeed(2*abesalrs.RecommendedSeedLen)

		// crypto scheme =  abecryptoxparam.CryptoSchemePQRingCT
		entropy := make([]byte, SeedLength)
		_, err := rand.Read(entropy)
		if err != nil {
			return 0, 0, nil, 0, errors.New("rand.Read() error in Seed()")
		}
		cryptoScheme := abecryptoxparam.CryptoSchemePQRingCT
		//crypto scheme =  abecryptoxparam.CryptoSchemePQRingCTX
		// In current version, we use a fixed crypto scheme for all new wallet
		//cryptoScheme := abecryptoxparam.CryptoSchemePQRingCTX
		//entropy, err := NewEntropy(SeedLength)
		//if err != nil {
		//	return 0, 0, nil, 0, errors.New("fail to generate entropy")
		//}

		mnemonics, err := EntropyToWords(cryptoScheme, entropy, wordlists.English)
		if err != nil {
			return 0, 0, nil, 0, errors.New("fail to convert entropy to mnemonic")
		}

		seed, err := WordsToSeed(cryptoScheme, mnemonics, wordlists.EnglishMap)
		if err != nil {
			return 0, 0, nil, 0, errors.New("fail to generate seed")
		}

		// Ascertain the wallet privacy level.
		privacyLevel, err := PrivacyLevel(reader, cryptoScheme)
		if err != nil {
			return 0, 0, nil, 0, errors.New("rand.Read() error in Seed()")
		}

		fmt.Println("Your wallet's generation seed is: ")
		fmt.Printf("%x\n", seed)
		fmt.Println("Your wallet's crypto version is: ", cryptoScheme)
		//fmt.Println("Your wallet's privacy level is: ", privacyLevel)
		fmt.Println("Your wallet's mnemonic list is: ")
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
				return 0, 0, nil, 0, err
			}
			confirmSeed = strings.TrimSpace(confirmSeed)
			confirmSeed = strings.Trim(confirmSeed, `"`)
			if confirmSeed == "OK" {
				break
			}
		}

		// add the cryptoScheme before seed
		// TODO Maybe we can remove this logic
		tmp := make([]byte, 4, 4+32)
		binary.BigEndian.PutUint32(tmp[0:4], uint32(cryptoScheme))
		seed = append(tmp, seed[:]...)

		return cryptoScheme, privacyLevel, seed, MAXCOUNTERADDRESS, nil
	}

	var cryptoScheme abecryptoxparam.CryptoScheme
	var seed []byte
	for {
		fmt.Print("Enter the crypto version:")
		cryptoSchemeStr, err := reader.ReadString('\n')
		cryptoSchemeStr = strings.TrimSpace(strings.ToLower(cryptoSchemeStr))
		cryptoSchemeInt, err := strconv.Atoi(cryptoSchemeStr)
		if err != nil {
			fmt.Print("Please enter right crypto version")
			continue
		}
		cryptoScheme = abecryptoxparam.CryptoScheme(cryptoSchemeInt)
		if cryptoScheme != abecryptoxparam.CryptoSchemePQRingCT {
			if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCTX {
				return 0, 0, nil, 0, errors.New("crypto version is supported by another wallet named abewalletmlp")
			}
			return 0, 0, nil, 0, errors.New("unsupported crypto scheme in current wallet version")
		}

		fmt.Print("Enter existing wallet mnemonic: ")
		mnemonicWords, err := reader.ReadString('\n')
		if err != nil {
			return 0, 0, nil, 0, err
		}
		mnemonicWords = strings.TrimSpace(strings.ToLower(mnemonicWords))
		mnemonics := strings.Split(mnemonicWords, ",")
		seed, err = WordsToSeed(cryptoScheme, mnemonics, wordlists.EnglishMap)
		if err != nil {
			return 0, 0, nil, 0, err
		}

		// add the cryptoScheme before seed
		// TODO Maybe we can remove this logic
		tmp := make([]byte, 4, 4+SeedLength)
		binary.BigEndian.PutUint32(tmp[0:4], uint32(cryptoScheme))
		seed = append(tmp, seed[:]...)

		if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCT {
			var recoveryAddressNum uint64
			fmt.Print("Please input the max No. of address to recover :")
			numStr, err := reader.ReadString('\n')
			numStr = strings.TrimSpace(numStr)
			recoveryAddressNum, err = strconv.ParseUint(numStr, 10, 0)
			if err != nil {
				return 0, 0, nil, 0, err
			}
			return cryptoScheme, 0, seed, recoveryAddressNum, nil
		}
		if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCTX {
			privacyLevel, err := PrivacyLevel(reader, cryptoScheme)
			if err != nil {
				return 0, 0, nil, 0, err
			}
			return cryptoScheme, privacyLevel, seed, 0, nil
		}
	}
}
