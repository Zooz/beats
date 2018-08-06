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

func defaultConfig() Config {

	var regs = []Reg{{
		`[\w\.]*@[\w\.]*`,
		`XX@XX.XX`,
		"Mask email",
	}}

	//fields := [...]string{"cvv","firstname","lastname","phone",}

	regexMatching := make(map[*regexp.Regexp]string)

	jsonFile, err := os.Open(os.Getenv("BLACK_LIST_PATH"))

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
