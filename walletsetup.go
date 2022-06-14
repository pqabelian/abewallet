package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/wordlists"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/internal/prompt"
	"github.com/abesuite/abewallet/wallet"
	"github.com/abesuite/abewallet/walletdb"
	_ "github.com/abesuite/abewallet/walletdb/bdb"
)

// networkDir returns the directory name of a network directory to hold wallet
// files.
func networkDir(dataDir string, chainParams *chaincfg.Params) string {
	netname := chainParams.Name

	// For now, we must always name the testnet data directory as "testnet"
	// and not "testnet3" or any other version, as the chaincfg testnet3
	// paramaters will likely be switched to being named "testnet3" in the
	// future.  This is done to future proof that change, and an upgrade
	// plan to move the testnet3 data directory can be worked out later.
	if chainParams.Net == wire.TestNet3 {
		netname = "testnet"
	}

	return filepath.Join(dataDir, netname)
}

// convertLegacyKeystore converts all of the addresses in the passed legacy
// key store to the new waddrmgr.Manager format.  Both the legacy keystore and
// the new manager must be unlocked.

// createWallet prompts the user for information needed to generate a new wallet
// and generates the wallet accordingly.  The new wallet will reside at the
// provided path.
func createWallet(cfg *config) error {
	dbDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	loader := wallet.NewLoader(activeNet.Params, dbDir, true, 250)

	// When there is a legacy keystore, open it now to ensure any errors
	// don't end up exiting the process after the user has spent time
	// entering a bunch of information.
	var err error
	if cfg.Create {
		// Start by prompting for the private passphrase.  When there is an
		// existing keystore, the user will be promped for that passphrase,
		// otherwise they will be prompted for a new one.
		reader := bufio.NewReader(os.Stdin)
		privPass, err := prompt.PrivatePass(reader)
		if err != nil {
			return err
		}

		// When there exists a legacy keystore, unlock it now and set up a
		// callback to import all keystore keys into the new walletdb
		// wallet

		// Ascertain the public passphrase.  This will either be a value
		// specified by the user or the default hard-coded public passphrase if
		// the user does not want the additional public data encryption.
		pubPass, err := prompt.PublicPass(reader, privPass,
			[]byte(cfg.WalletPass))
		if err != nil {
			return err
		}

		// Ascertain the wallet generation seed.  This will either be an
		// automatically generated value the user has already confirmed or a
		// value the user has entered which has already been validated.
		seed, end, err := prompt.Seed(reader)
		if err != nil {
			return err
		}

		fmt.Println("Creating the wallet...")
		w, err := loader.CreateNewWallet(pubPass, privPass, seed[4:], end, time.Now())
		if err != nil {
			return err
		}

		//w.Manager.Close()
		w.Manager.Close()
		fmt.Println("The wallet has been created successfully.")
	} else if cfg.NonInteractiveCreate {
		var seed []byte
		var mnemonics []string
		if !cfg.WithMnemonic {
			seed = make([]byte, prompt.SeedLength)
			_, err = rand.Read(seed)
			if err != nil {
				return err
			}
			mnemonics = prompt.SeedToWords(seed, wordlists.English)
			tmp := make([]byte, 4, 4+prompt.SeedLength)
			binary.BigEndian.PutUint32(tmp[0:4], uint32(abecryptoparam.CryptoSchemePQRingCT))
			seed = append(tmp, seed[:]...)
			cfg.MyRestoreNumber = 0xFFFF_FFFF_FFFF_FFFF
		} else {
			versionStr := strings.TrimSpace(strings.ToLower(cfg.MyVersion))
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				return err
			}
			mnemonics = strings.Split(cfg.MyMnemonic, ",")
			seed = prompt.WordsToSeed(mnemonics, wordlists.EnglishMap)
			if len(seed) != prompt.SeedLength+1 {
				return errors.New("Invalid mnemonic word list specified\n")
			}
			seedH := chainhash.DoubleHashH(seed[:32])
			if !bytes.Equal(seedH[:1], seed[prompt.SeedLength:]) {
				return errors.New("Invalid mnemonic word list specified\n")
			}
			seed = seed[:prompt.SeedLength]
			// add the cryptoScheme before seed
			tmp := make([]byte, 4, 4+prompt.SeedLength)
			binary.BigEndian.PutUint32(tmp[0:4], uint32(version))
			seed = append(tmp, seed[:]...)
		}
		fmt.Println(binary.BigEndian.Uint32(seed[:4]))
		fmt.Printf("%x\n", seed[4:])
		fmt.Printf("%v\n", strings.Join(mnemonics, ","))
		if cfg.MyWalletPass == "" {
			cfg.MyWalletPass = wallet.InsecurePubPassphrase
		}
		w, err := loader.CreateNewWallet([]byte(cfg.MyWalletPass), []byte(cfg.MyPassword), seed[4:], cfg.MyRestoreNumber, time.Now())
		if err != nil {
			return err
		}

		w.Manager.Close()
	}

	return nil
}

// createSimulationWallet is intended to be called from the rpcclient
// and used to create a wallet for actors involved in simulations.
func createSimulationWallet(cfg *config) error {
	// Simulation wallet password is 'password'.
	privPass := []byte("password")

	// Public passphrase is the default.
	pubPass := []byte(wallet.InsecurePubPassphrase)

	netDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)

	// Create the wallet.
	dbPath := filepath.Join(netDir, walletDbName)
	fmt.Println("Creating the wallet...")

	// Create the wallet database backed by bolt db.
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Create the wallet.
	err = wallet.Create(db, pubPass, privPass, nil, 0, activeNet.Params, time.Now())
	if err != nil {
		return err
	}

	fmt.Println("The wallet has been created successfully.")
	return nil
}

// checkCreateDir checks that the path exists and is a directory.
// If path does not exist, it is created.
func checkCreateDir(path string) error {
	if fi, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Attempt data directory creation
			if err = os.MkdirAll(path, 0700); err != nil {
				return fmt.Errorf("cannot create directory: %s", err)
			}
		} else {
			return fmt.Errorf("error checking directory: %s", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("path '%s' is not a directory", path)
		}
	}

	return nil
}
