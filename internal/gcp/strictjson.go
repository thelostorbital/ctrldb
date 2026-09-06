// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var errInvalidJSON = errors.New("invalid provider JSON")

var projectedJSONKeys = map[string]struct{}{
	"IPProtocol": {}, "account": {}, "allowed": {}, "auth": {}, "config": {}, "core": {}, "deleted": {},
	"deprecated": {}, "direction": {}, "disabled": {}, "email": {}, "guestCpus": {},
	"ipCidrRange": {}, "isSharedCpu": {}, "lifecycleState": {}, "location": {}, "memoryMb": {},
	"metadata": {}, "name": {}, "nats": {}, "ports": {}, "project": {}, "projectId": {}, "projectNumber": {},
	"region": {}, "secondaryIpRanges": {}, "selfLink": {}, "sourceRanges": {}, "state": {},
	"status": {}, "uniqueId": {}, "zone": {}, "impersonate_service_account": {},
}

func decodeStrictJSON(data []byte, target any) error {
	return decodeProviderJSON(data, target, true)
}

func decodeVersionJSON(data []byte, target any) error {
	return decodeProviderJSON(data, target, false)
}

func decodeProviderJSON(data []byte, target any, enforceProjectedKeys bool) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || !utf8.Valid(data) || int64(len(data)) > readStdoutLimit {
		return errInvalidJSON
	}
	duplicateDecoder := json.NewDecoder(bytes.NewReader(data))
	duplicateDecoder.UseNumber()
	if err := inspectJSONValue(duplicateDecoder, enforceProjectedKeys); err != nil {
		return errInvalidJSON
	}
	if token, err := duplicateDecoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return errInvalidJSON
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder, enforceProjectedKeys bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key")
			}
			if enforceProjectedKeys {
				if _, known := projectedJSONKeys[key]; !known {
					return fmt.Errorf("unknown object key")
				}
			}
			seen[key] = struct{}{}
			if valueErr := inspectJSONValue(decoder, enforceProjectedKeys); valueErr != nil {
				return valueErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return fmt.Errorf("object is not closed")
		}
	case '[':
		for decoder.More() {
			if valueErr := inspectJSONValue(decoder, enforceProjectedKeys); valueErr != nil {
				return valueErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return fmt.Errorf("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	return nil
}
