// Copyright 2014 Google Inc. All rights reserved.
//
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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	var electionUuid = flag.String("uuid", "", "The uuid of the election to download")
	var heliosServer = flag.String("server", "https://participauchile.cl/vota/", "The server to download the election from")
	var bundleFile = flag.String("bundle", "", "The file to write the bundle into")
	var download = flag.Bool("download", true, "Whether or not to download the bundle")
	var verify = flag.Bool("verify", false, "Whether or not to verify the downloaded bundle")
	var write = flag.Bool("write", true, "Whether or not to write the downloaded bundle to a file")
	var username = flag.String("username", "", "Username used in admin panel. Required for private elections.")
	var password = flag.String("password", "", "Password used in admin panel. Required for private elections.")
	flag.Parse()

	if len(*electionUuid) == 0 && len(*bundleFile) == 0 {
		fmt.Fprintln(os.Stderr, "Must provide an election uuid")
		return
	}

	if (!*download || *write) && len(*bundleFile) == 0 {
		fmt.Fprintln(os.Stderr, "Must provide a bundle file name")
		return
	}

	var b *ElectionBundle
	var err error
	if *download {
		fmt.Println("Downloading election information and ballots. This might take a long time.")
		b, err = Download(*heliosServer, *electionUuid, *username, *password)
		if err != nil {
			panic(err)
		}

		if *write {
			serialized, err := json.Marshal(b)
			if err != nil {
				panic(err)
			}

			err = ioutil.WriteFile(*bundleFile, serialized, 0644)
			if err != nil {
				panic(err)
			}
		}
	} else {
		fmt.Println("Loading election information and ballots. This might take a long time.")
		serialized, err := ioutil.ReadFile(*bundleFile)
		if err != nil {
			panic(err)
		}

		b = new(ElectionBundle)
		err = UnmarshalJSON(serialized, b)
		if err != nil {
			panic(err)
		}

		fmt.Println("Deserializing election information and ballots.")
		if err = b.Instantiate(); err != nil {
			panic(err)
		}
	}

	if *verify {
		fmt.Println("Verifying election.")
		if b.Verify() {
			fmt.Println("The election passes verification")

			fmt.Println("The results are as follows:")
			lr := b.Election.LabelResults(b.Result.ResultsTotal)
			fmt.Printf("%s", lr.toString(b.Election.Normalization))
		} else {
			if b.Result.ResultsTotal == nil {
				fmt.Fprintln(os.Stderr, "The election has not yet published results")
			} else {
				fmt.Fprintln(os.Stderr, "The election fails verification")
			}
		}
	}
}
