// Copyright © 2017 Insurance
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
)

var shares int
var threshold int
var inputFile string

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal a secret file",
	Long:  `Encrypts input file with generated key, returns key shares and insurance file`,
	Run: func(cmd *cobra.Command, args []string) {
		secret, parts, err := gShares(shares, threshold)
		if err != nil {
			panic(err)
		}

		var nonce [24]byte
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			panic(err)
		}

		var secretKey [32]byte
		copy(secretKey[:], secret)

		b, err := ioutil.ReadFile(inputFile)
		if err != nil {
			panic(err)
		}

		encrypted := secretbox.Seal(nonce[:], b, &nonce, &secretKey)
		newName := inputFile + ".insurance"
		err = ioutil.WriteFile(newName, encrypted, 0644)
		if err != nil {
			panic(err)
		}

		for i, part := range parts {
			name := fmt.Sprintf(inputFile+".key%d", i+1)
			err = ioutil.WriteFile(name, part, 0644)
			if err != nil {
				panic(err)
			}
		}

		fmt.Println("Sealed.")
	},
}

func init() {
	RootCmd.AddCommand(sealCmd)
	sealCmd.Flags().IntVar(&shares, "shares", 5, "Number of generated shares")
	sealCmd.Flags().IntVar(&threshold, "threshold", 4, "Number of shares required to open")
	sealCmd.Flags().StringVar(&inputFile, "input", "", "Input file for encryption")
}

func gShares(shares int, threshold int) ([]byte, [][]byte, error) {
	var secret [32]byte
	if _, err := io.ReadFull(rand.Reader, secret[:]); err != nil {
		return nil, nil, err
	}
	parts, err := shamir.Split(secret[:], shares, threshold)
	if err != nil {
		return nil, nil, err
	}
	return secret[:], parts, nil
}
