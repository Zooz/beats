// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package mask_sensitive_data

import (
	"regexp"
	"os"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"io"
)

type Reg struct {
	name        string
	value       string
	description string
}

type LoadedConfig struct {
	Fields []string
}

// Config for mask_sensitive_data processor.
type Config struct {
	fields        []string
	regexMatching map[*regexp.Regexp]string
}

// write as it downloads and not load the whole file into memory.
func DownloadFile(filepath string, url string) error {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	fmt.Println("Downloading filebeat black list file: " + url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func defaultConfig() Config {

	var regs = []Reg{{
		`[\w\.]*@[\w\.]*`,
		`XX@XX.XX`,
		"Mask email",
	}}


	regexMatching := make(map[*regexp.Regexp]string)

	fileUrl := os.Getenv("BLACK_LIST_URL");

	err := DownloadFile("black-list.json", fileUrl)
	if err != nil {
		panic(err)
	}


	jsonFile, err := os.Open("black-list.json")

	if err != nil {
		fmt.Println(err)
		fmt.Println("Problem opening black list file")
	} else {
		fmt.Println("Successfully Opened black list file")
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	var loadedConfig LoadedConfig
	json.Unmarshal(byteValue, &loadedConfig)

	fmt.Println(loadedConfig.Fields)
	for _, field := range loadedConfig.Fields{
		fmt.Println("Black listing field " + field)
		regexMatching[regexp.MustCompile(`("`+field+`"):[^,}]*`)] = `$1:"xxxx"`
	}

	for _, reg := range regs {
		regexMatching[regexp.MustCompile(reg.name)] = reg.value
	}

	return Config{
		regexMatching: regexMatching,
	}
}
