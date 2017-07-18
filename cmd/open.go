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
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
)

var encFile string
var inputShares []string

// openCmd represents the open command
var openCmd = &cobra.Command{
	Use:   "open",
	Short: "Opens an insurance file",
	Long:  `Using n input shares and encrypted insurance file, if threshold reached, decrypt insurance input file`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("open called")

		var parts [][]byte
		for _, share := range inputShares {
			f, err := ioutil.ReadFile(share)
			if err != nil {
				panic(err)
			}
			parts = append(parts, f)
		}

		recomb, err := shamir.Combine(parts)
		if err != nil {
			panic(err)
		}
		var secretKey [32]byte
		copy(secretKey[:], recomb)

		encrypted, err := ioutil.ReadFile(encFile)
		if err != nil {
			panic(err)
		}

		var decryptNonce [24]byte
		copy(decryptNonce[:], encrypted[:24])
		decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secretKey)
		if !ok {
			panic("decryption error")
		}

		newName := encFile + ".out"
		err = ioutil.WriteFile(newName, decrypted, 0644)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	RootCmd.AddCommand(openCmd)
	openCmd.Flags().StringVar(&encFile, "input", "", "Input file for encryption")
	openCmd.Flags().StringSliceVar(&inputShares, "shares", nil, "Input shares")
}
