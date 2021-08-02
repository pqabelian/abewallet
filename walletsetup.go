package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abepqringct"
	"github.com/abesuite/abec/abecrypto/abesalrs"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/wordlists"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/btcec"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/internal/legacy/keystore"
	"github.com/abesuite/abewallet/internal/prompt"
	"github.com/abesuite/abewallet/waddrmgr"
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
func convertLegacyKeystore(legacyKeyStore *keystore.Store, w *wallet.Wallet) error {
	netParams := legacyKeyStore.Net()
	blockStamp := waddrmgr.BlockStamp{
		Height: 0,
		Hash:   *netParams.GenesisHash,
	}
	for _, walletAddr := range legacyKeyStore.ActiveAddresses() {
		switch addr := walletAddr.(type) {
		case keystore.PubKeyAddress:
			privKey, err := addr.PrivKey()
			if err != nil {
				fmt.Printf("WARN: Failed to obtain private key "+
					"for address %v: %v\n", addr.Address(),
					err)
				continue
			}

			wif, err := abeutil.NewWIF((*btcec.PrivateKey)(privKey),
				netParams, addr.Compressed())
			if err != nil {
				fmt.Printf("WARN: Failed to create wallet "+
					"import format for address %v: %v\n",
					addr.Address(), err)
				continue
			}

			_, err = w.ImportPrivateKey(waddrmgr.KeyScopeBIP0044,
				wif, &blockStamp, false)
			if err != nil {
				fmt.Printf("WARN: Failed to import private "+
					"key for address %v: %v\n",
					addr.Address(), err)
				continue
			}

		case keystore.ScriptAddress:
			_, err := w.ImportP2SHRedeemScript(addr.Script())
			if err != nil {
				fmt.Printf("WARN: Failed to import "+
					"pay-to-script-hash script for "+
					"address %v: %v\n", addr.Address(), err)
				continue
			}

		default:
			fmt.Printf("WARN: Skipping unrecognized legacy "+
				"keystore type: %T\n", addr)
			continue
		}
	}

	return nil
}

// createWallet prompts the user for information needed to generate a new wallet
// and generates the wallet accordingly.  The new wallet will reside at the
// provided path.
func createWallet(cfg *config) error {
	dbDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	loader := wallet.NewLoader(activeNet.Params, dbDir, true, 250)

	// When there is a legacy keystore, open it now to ensure any errors
	// don't end up exiting the process after the user has spent time
	// entering a bunch of information.
	netDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	keystorePath := filepath.Join(netDir, keystore.Filename)
	// TODO(abe): the legacy key store may be can cancel for abe, it should be used
	//  to compatible to old version of bitcoin core...
	//  we just have one version at least now
	var legacyKeyStore *keystore.Store
	_, err := os.Stat(keystorePath)
	if err != nil && !os.IsNotExist(err) {
		// A stat error not due to a non-existant file should be
		// returned to the caller.
		return err
	} else if err == nil {
		// Keystore file exists.
		legacyKeyStore, err = keystore.OpenDir(netDir)
		if err != nil {
			return err
		}
	}

	// Start by prompting for the private passphrase.  When there is an
	// existing keystore, the user will be promped for that passphrase,
	// otherwise they will be prompted for a new one.
	reader := bufio.NewReader(os.Stdin)
	privPass, err := prompt.PrivatePass(reader, legacyKeyStore)
	if err != nil {
		return err
	}

	// When there exists a legacy keystore, unlock it now and set up a
	// callback to import all keystore keys into the new walletdb
	// wallet
	if legacyKeyStore != nil {
		//TODO(abe): privpass should be input by user ... not holding in the memory
		// Anyway, the keystore would be deleted
		err = legacyKeyStore.Unlock(privPass)
		if err != nil {
			return err
		}

		// Import the addresses in the legacy keystore to the new wallet if
		// any exist, locking each wallet again when finished.
		loader.RunAfterLoad(func(w *wallet.Wallet) {
			defer legacyKeyStore.Lock()

			fmt.Println("Importing addresses from existing wallet...")

			lockChan := make(chan time.Time, 1)
			defer func() {
				lockChan <- time.Time{}
			}()
			err := w.Unlock(privPass, lockChan)
			if err != nil {
				fmt.Printf("ERR: Failed to unlock new wallet "+
					"during old wallet key import: %v", err)
				return
			}

			err = convertLegacyKeystore(legacyKeyStore, w)
			if err != nil {
				fmt.Printf("ERR: Failed to import keys from old "+
					"wallet format: %v", err)
				return
			}

			// Remove the legacy key store.
			err = os.Remove(keystorePath)
			if err != nil {
				fmt.Printf("WARN: Failed to remove legacy wallet "+
					"from'%s'\n", keystorePath)
			}
		})
	}

	// Ascertain the public passphrase.  This will either be a value
	// specified by the user or the default hard-coded public passphrase if
	// the user does not want the additional public data encryption.
	pubPass, err := prompt.PublicPass(reader, privPass,
		[]byte(wallet.InsecurePubPassphrase), []byte(cfg.WalletPass))
	if err != nil {
		return err
	}

	// Ascertain the wallet generation seed.  This will either be an
	// automatically generated value the user has already confirmed or a
	// value the user has entered which has already been validated.
	seed, err := prompt.Seed(reader)
	if err != nil {
		return err
	}

	fmt.Println("Creating the wallet...")
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	if err != nil {
		return err
	}

	w.Manager.Close()
	fmt.Println("The wallet has been created successfully.")
	return nil
}
func createWalletAbe(cfg *config) error {
	dbDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	loader := wallet.NewLoader(activeNet.Params, dbDir, true, 250)

	// When there is a legacy keystore, open it now to ensure any errors
	// don't end up exiting the process after the user has spent time
	// entering a bunch of information.
	netDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	keystorePath := filepath.Join(netDir, keystore.Filename)
	var legacyKeyStore *keystore.Store
	_, err := os.Stat(keystorePath)
	if err != nil && !os.IsNotExist(err) {
		// A stat error not due to a non-existant file should be
		// returned to the caller.
		return err
	} else if err == nil {
		// Keystore file exists.
		legacyKeyStore, err = keystore.OpenDir(netDir)
		if err != nil {
			return err
		}
	}

	if cfg.Create {
		// Start by prompting for the private passphrase.  When there is an
		// existing keystore, the user will be promped for that passphrase,
		// otherwise they will be prompted for a new one.
		reader := bufio.NewReader(os.Stdin)
		privPass, err := prompt.PrivatePass(reader, legacyKeyStore)
		if err != nil {
			return err
		}

		// When there exists a legacy keystore, unlock it now and set up a
		// callback to import all keystore keys into the new walletdb
		// wallet
		if legacyKeyStore != nil {
			err = legacyKeyStore.Unlock(privPass)
			if err != nil {
				return err
			}

			// Import the addresses in the legacy keystore to the new wallet if
			// any exist, locking each wallet again when finished.
			loader.RunAfterLoad(func(w *wallet.Wallet) {
				defer legacyKeyStore.Lock()

				fmt.Println("Importing addresses from existing wallet...")

				lockChan := make(chan time.Time, 1)
				defer func() {
					lockChan <- time.Time{}
				}()
				err := w.Unlock(privPass, lockChan)
				if err != nil {
					fmt.Printf("ERR: Failed to unlock new wallet "+
						"during old wallet key import: %v", err)
					return
				}

				err = convertLegacyKeystore(legacyKeyStore, w)
				if err != nil {
					fmt.Printf("ERR: Failed to import keys from old "+
						"wallet format: %v", err)
					return
				}

				// Remove the legacy key store.
				err = os.Remove(keystorePath)
				if err != nil {
					fmt.Printf("WARN: Failed to remove legacy wallet "+
						"from'%s'\n", keystorePath)
				}
			})
		}

		// Ascertain the public passphrase.  This will either be a value
		// specified by the user or the default hard-coded public passphrase if
		// the user does not want the additional public data encryption.
		pubPass, err := prompt.PublicPass(reader, privPass,
			[]byte(wallet.InsecurePubPassphrase), []byte(cfg.WalletPass))
		if err != nil {
			return err
		}

		// Ascertain the wallet generation seed.  This will either be an
		// automatically generated value the user has already confirmed or a
		// value the user has entered which has already been validated.
		seed, err := prompt.Seed(reader)
		if err != nil {
			return err
		}

		fmt.Println("Creating the wallet...")
		w, err := loader.CreateNewWalletAbe(pubPass, privPass, seed, time.Now())
		if err != nil {
			return err
		}

		//w.Manager.Close()
		w.ManagerAbe.Close()
		fmt.Println("The wallet has been created successfully.")
	} else if cfg.NonInteractiveCreate {
		var seed []byte
		var mnemonics []string
		if !cfg.WithMnemonic {
			seed, _, _, _, err = abepqringct.MasterKeyGen(nil, abecrypto.CryptoSchemePQRINGCT)
			if err != nil {
				return err
			}
			mnemonics = prompt.SeedToWords(seed[4:], wordlists.English)
		} else {
			versionStr := strings.TrimSpace(strings.ToLower(cfg.MyVersion))
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				return err
			}
			mnemonics = strings.Split(cfg.MyMnemonic, ",")
			seed = prompt.WordsToSeed(mnemonics, wordlists.EnglishMap)
			if len(seed) != 66 {
				return errors.New("Invalid mnemonic word list specified\n")
			}
			seedH := chainhash.DoubleHashH(seed[:64])
			if !bytes.Equal(seedH[:2], seed[64:]) {
				return errors.New("Invalid mnemonic word list specified\n")
			}
			seed = seed[:64]
			if len(seed) <abesalrs.MinSeedBytes || len(seed) > abesalrs.MaxSeedBytes {
				return errors.New("Invalid mnemonic word list specified\n")
			}
			// add the cryptoScheme before seed
			tmp := make([]byte, 4, 4+64)
			binary.BigEndian.PutUint32(tmp[0:4], uint32(version))
			seed = append(tmp, seed[:]...)
		}
		fmt.Println(binary.BigEndian.Uint32(seed[:4]))
		fmt.Printf("%v\n", strings.Join(mnemonics, ","))
		w, err := loader.CreateNewWalletAbe([]byte(wallet.InsecurePubPassphrase), []byte(cfg.MyPassword), seed, time.Now())
		if err != nil {
			return err
		}

		w.ManagerAbe.Close()
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
	err = wallet.Create(db, pubPass, privPass, nil, activeNet.Params, time.Now())
	if err != nil {
		return err
	}

	fmt.Println("The wallet has been created successfully.")
	return nil
}
//TODO(abe):
func createSimulationWalletAbe(cfg *config) error {
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
	err = wallet.CreateAbe(db, pubPass, privPass, nil, activeNet.Params, time.Now())
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
