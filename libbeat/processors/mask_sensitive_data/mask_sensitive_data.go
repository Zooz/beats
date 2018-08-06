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
	"fmt"
	"github.com/pkg/errors"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/processors"
	"reflect"
	"time"
)

func init() {
	processors.RegisterPlugin("mask_sensitive_data", newMaskingProcessor)
}

type maskSensitiveData struct {
	config     Config
}

const (
	processorName   = "mask_sensitive_data"
)

func newMaskingProcessor(cfg *common.Config) (processors.Processor, error) {
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return nil, errors.Wrapf(err, "fail to unpack the %v configuration", processorName)
	}

	p := &maskSensitiveData{
		config: config,
	}
	return p, nil
}

// Run checks the given event for sensitive data and mask it
func (p *maskSensitiveData) Run(event *beat.Event) (*beat.Event, error) {
	fmt.Println("Printing the event object:")
	start := time.Now()
	message, err := event.Fields.GetValue("message")
	if err == nil {
		fmt.Println(reflect.TypeOf(message))
	}

	if str, ok := message.(string); ok {
		config := defaultConfig()
		s := str
		for re, rep := range config.regexMatching {
			fmt.Println("Applying regex pattern " + re.String())
			s = re.ReplaceAllString(s, rep)
		}

		fmt.Println(s)
		event.Fields.Put("message", s)
		elapsed := time.Since(start)
		fmt.Println("Masking took %s", elapsed)
	} else {
		fmt.Println("Could not convert event message to string")
	}

	return event, nil
}


func (p maskSensitiveData) String() string {
	return fmt.Sprintf("%v", processorName)
}
