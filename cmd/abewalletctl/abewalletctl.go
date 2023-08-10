package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/abesuite/abec/abejson"
	"github.com/abesuite/abec/chainhash"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	showHelpMessage = "Specify -h to show available options"
	listCmdMessage  = "Specify -l to list available commands"
)

// commandUsage display the usage for a specific command.
func commandUsage(method string) {
	usage, err := abejson.MethodUsageText(method)
	if err != nil {
		// This should never happen since the method was already checked
		// before calling this function, but be safe.
		fmt.Fprintln(os.Stderr, "Failed to obtain command usage:", err)
		return
	}

	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s\n", usage)
}

// usage displays the general usage when the help flag is not displayed and
// and an invalid command was specified.  The commandUsage function is used
// instead when a valid command was specified.
func usage(errorMessage string) {
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	fmt.Fprintln(os.Stderr, errorMessage)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "  %s [OPTIONS] <command> <args...>\n\n",
		appName)
	fmt.Fprintln(os.Stderr, showHelpMessage)
	fmt.Fprintln(os.Stderr, listCmdMessage)
}

func main() {
	cfg, args, err := loadConfig()
	if err != nil {
		os.Exit(1)
	}
	if len(args) < 1 {
		usage("No command specified")
		os.Exit(1)
	}

	// Ensure the specified method identifies a valid registered command and
	// is one of the usable types.
	method := args[0]
	if _, ok := utilityHandlers[method]; !ok {
		usageFlags, err := abejson.MethodUsageFlags(method)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unrecognized command '%s'\n", method)
			fmt.Fprintln(os.Stderr, listCmdMessage)
			os.Exit(1)
		}
		if usageFlags&unusableFlags != 0 {
			fmt.Fprintf(os.Stderr, "The '%s' command can only be used via "+
				"websockets\n", method)
			fmt.Fprintln(os.Stderr, listCmdMessage)
			os.Exit(1)
		}
	}

	// Convert remaining command line args to a slice of interface values
	// to be passed along as parameters to new command creation function.
	//
	// Since some commands, such as submitblock, can involve data which is
	// too large for the Operating System to allow as a normal command line
	// parameter, support using '-' as an argument to allow the argument
	// to be read from a stdin pipe.
	//bio := bufio.NewReader(os.Stdin)
	params := make([]interface{}, 0, len(args[1:]))
	num := 1
	for _, arg := range args[1:] {
		if arg == "-" {
			filePath := filepath.Join(abecHomeDir, "arg"+strconv.Itoa(num))
			param, err := ioutil.ReadFile(filePath)
			//param, err := bio.ReadString('\n')
			if err != nil && err != io.EOF {
				fmt.Fprintf(os.Stderr, "Failed to read data "+
					"from file %v: %v\n", filePath, err)
				os.Exit(1)
			}
			if err == io.EOF && len(param) == 0 {
				fmt.Fprintln(os.Stderr, "Not enough lines "+
					"provided on stdin")
				os.Exit(1)
			}
			//param = strings.TrimRight(param, "\r\n")
			params = append(params, string(param))
			continue
		}

		params = append(params, arg)
	}

	// check utility
	if handler, ok := utilityHandlers[method]; ok {
		result, err := handler(params, cfg)
		if err != nil {
			usage(fmt.Sprintf("Error occurs:%s", err))
			os.Exit(1)
		}
		fmt.Println(result)
		os.Exit(0)
	}
	// Attempt to create the appropriate command using the arguments
	// provided by the user.
	cmd, err := abejson.NewCmd(method, params...)
	if err != nil {
		// Show the error along with its error code when it's a
		// abejson.Error as it reallistcally will always be since the
		// NewCmd function is only supposed to return errors of that
		// type.
		if jerr, ok := err.(abejson.Error); ok {
			fmt.Fprintf(os.Stderr, "%s command: %v (code: %s)\n",
				method, err, jerr.ErrorCode)
			commandUsage(method)
			os.Exit(1)
		}

		// The error is not a abejson.Error and this really should not
		// happen.  Nevertheless, fallback to just showing the error
		// if it should happen due to a bug in the package.
		fmt.Fprintf(os.Stderr, "%s command: %v\n", method, err)
		commandUsage(method)
		os.Exit(1)
	}

	// Marshal the command into a JSON-RPC byte slice in preparation for
	// sending it to the RPC server.
	marshalledJSON, err := abejson.MarshalCmd(1, cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Send the JSON-RPC request to the server using the user-specified
	// connection configuration.
	result, err := sendPostRequest(marshalledJSON, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Choose how to display the result based on its type.
	strResult := string(result)
	if strings.HasPrefix(strResult, "{") || strings.HasPrefix(strResult, "[") {
		var dst bytes.Buffer
		if err := json.Indent(&dst, result, "", "  "); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to format result: %v",
				err)
			os.Exit(1)
		}
		fmt.Println(dst.String())

	} else if strings.HasPrefix(strResult, `"`) {
		var str string
		if err := json.Unmarshal(result, &str); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal result: %v",
				err)
			os.Exit(1)
		}
		fmt.Println(str)

	} else if strResult != "null" {
		fmt.Println(strResult)
	}
}

var utilityHandlers = map[string]func(params []interface{}, cfg *config) (string, error){
	"balanceaggregate": aggregateBalances,
}

type UTXO struct {
	RingHash     string
	TxHash       string
	Index        uint8
	FromCoinbase bool
	Amount       uint64
	Height       int64
	UTXOHash     chainhash.Hash
	UTXOHashStr  string
	Allocated    bool
}

func aggregateBalances(params []interface{}, cfg *config) (string, error) {
	// total,group,fee
	if len(params) < 7 {
		return "", fmt.Errorf("non-enough parameters")
	}
	walletpass := toString(params[0])
	total, err := strconv.ParseUint(toString(params[1]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'total' must be a unsigned integer")
	}
	group, err := strconv.ParseUint(toString(params[2]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'group' must be a unsigned integer")
	}
	splitPercent, err := strconv.ParseUint(toString(params[3]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'split percent' must be a unsigned integer")
	}
	rangeStart, err := strconv.ParseUint(toString(params[4]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'range start' must be a unsigned integer")
	}
	rangeEnd, err := strconv.ParseUint(toString(params[5]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'range end' must be a unsigned integer")
	}
	fee, err := strconv.ParseUint(toString(params[6]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'transaction fee' must be a unsigned integer")
	}
	coinbaseOnly, err := strconv.ParseBool(toString(params[7]))
	if err != nil {
		return "", fmt.Errorf("wrong format parameters, 'coinbase only' must be a boolean value")
	}

	// parameter sanctity
	unlockWallet := func(timeout int64) error {
		marshalledJSON, err := abejson.MarshalCmd(1, &abejson.WalletPassphraseCmd{
			Passphrase: walletpass,
			Timeout:    timeout,
		})
		if err != nil {
			return fmt.Errorf("can not unlock wallet: %v", err)
		}
		_, err = sendPostRequest(marshalledJSON, cfg)
		if err != nil {
			return fmt.Errorf("can not unlock wallet: %v", err)
		}
		return nil
	}
	lockWallet := func() error {
		marshalledJSON, err := abejson.MarshalCmd(1, &abejson.WalletLockCmd{})
		if err != nil {
			return fmt.Errorf("can not lock wallet: %v", err)
		}
		_, err = sendPostRequest(marshalledJSON, cfg)
		if err != nil {
			return fmt.Errorf("can not lock wallet: %v", err)
		}
		return nil
	}
	if err = unlockWallet(10); err != nil {
		return "", err
	}
	if err = lockWallet(); err != nil {
		return "", err
	}
	if total <= 0 || group <= 0 || fee <= 0 || group > 5 || total < group ||
		splitPercent >= 100 {
		return "", fmt.Errorf("invalid format parameters")
	}

	// acquire utxo list
	marshalledJSON, err := abejson.MarshalCmd(1, &abejson.ListUnspentAbeCmd{})
	if err != nil {
		return "", fmt.Errorf("can not acquire utxo list")
	}
	resBytes, err := sendPostRequest(marshalledJSON, cfg)
	if err != nil {
		return "", fmt.Errorf("can not acquire utxo list: %v", err)
	}
	utxoList := make([]*UTXO, 0, 100)
	err = json.Unmarshal(resBytes, &utxoList)
	if err != nil {
		return "", fmt.Errorf("can not acquire utxo list")
	}
	// filter utxo list by range
	filteredUTXOList := make([]*UTXO, 0, len(utxoList))
	for i := 0; i < len(utxoList); i++ {
		if rangeStart <= utxoList[i].Amount && utxoList[i].Amount < rangeEnd && (!coinbaseOnly || (coinbaseOnly && utxoList[i].FromCoinbase)) {
			filteredUTXOList = append(filteredUTXOList, utxoList[i])
		}
	}
	utxoList = filteredUTXOList

	type Address struct {
		No_  uint64 `json:"No,omitempty"`
		Addr string `json:"addr,omitempty"`
	}
	if len(utxoList) < int(total) {
		total = uint64(len(utxoList))
	}
	totalRound := int((total + group - 1) / group)
	// divide groups
	round := 0
	zero := 0
	fone := float64(1)
	feeSpecified := float64(fee)
	transactionHashStrs := make([]string, (total+group-1)/group)
	for ; round < totalRound; round++ {
		// acquire new addresses
		newAddressNum := 1
		if splitPercent != 0 {
			newAddressNum += 1
		}
		marshalledJSON, err = abejson.MarshalCmd(1, &abejson.GenerateAddressCmd{
			Num: &newAddressNum,
		})
		if err != nil {
			return "", fmt.Errorf("can not acquire new address: %v", err)
		}
		if err = unlockWallet(60); err != nil {
			return "", err
		}
		resBytes, err = sendPostRequest(marshalledJSON, cfg)
		if err != nil {
			return "", fmt.Errorf("can not acquire new address: %v", err)
		}
		addresses := make([]*Address, 0, newAddressNum)
		err = json.Unmarshal(resBytes, &addresses)
		if err != nil {
			return "", fmt.Errorf("can not acquire new address: %v", err)
		}
		if err = lockWallet(); err != nil {
			return "", err
		}

		addrIdx := 0
		cmd := &abejson.SendToAddressAbeCmd{
			Amounts: []abejson.Pair{
				{
					Address: addresses[addrIdx].Addr,
				},
			},
			MinConf:            &zero,
			ScaleToFeeSatPerKb: &fone,
			FeeSpecified:       &feeSpecified, // the fixed transaction fee
		}
		addrIdx += 1

		totalAmount := uint64(0)
		utxoStrs := make([]string, 0, 5)
		start := round * int(group)
		for offset := 0; offset < int(group) && start+offset < int(total) && start+offset < len(utxoList); offset++ {
			totalAmount += utxoList[start+offset].Amount
			utxoStrs = append(utxoStrs, utxoList[start+offset].UTXOHashStr)
		}

		if err := unlockWallet(60); err != nil {
			return "", fmt.Errorf("wrong format wallet passphrase: %v", err)
		}

		utxoSpecified := strings.Join(utxoStrs, ",")
		cmd.UTXOSpecified = &utxoSpecified
		cmd.Amounts[0].Amount = float64(totalAmount-fee) / 100 * (100 - float64(splitPercent))
		if splitPercent != 0 {
			cmd.Amounts = append(cmd.Amounts, abejson.Pair{
				Address: addresses[addrIdx].Addr,
				Amount:  float64(totalAmount-fee) - cmd.Amounts[0].Amount,
			})
			addrIdx += 1
			if rand.Intn(100) > 50 {
				cmd.Amounts[0], cmd.Amounts[1] = cmd.Amounts[1], cmd.Amounts[0]
			}
		}

		marshalledJSON, err = abejson.MarshalCmd(1, cmd)
		if err != nil {
			return "", fmt.Errorf("can not create transaction command: %v", err)
		}

		// Send the JSON-RPC request to the server using the user-specified
		// connection configuration.
		result, err := sendPostRequest(marshalledJSON, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		transactionHashStrs[round] = string(result[1 : 1+chainhash.MaxHashStringSize])
		if err = lockWallet(); err != nil {
			return "", fmt.Errorf("wrong format wallet passphrase: %v", err)
		}
	}

	resBytes, err = json.Marshal(transactionHashStrs)
	return string(resBytes), err
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.FormatInt(int64(v), 10)
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	}
	return ""
}
