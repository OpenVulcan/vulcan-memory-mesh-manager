// This file persists the manager-owned process registration with strict JSON rules.
// 此文件以严格 JSON 规则持久化管理器拥有的进程登记。
package processctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// loadRecord reads one bounded, strict process registration.
// loadRecord 读取一个有大小上限且严格解析的进程登记。
func loadRecord(path string) (processRecord, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return processRecord{}, false, nil
	}
	if err != nil {
		return processRecord{}, false, ErrStateCorrupt
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return processRecord{}, false, ErrStateCorrupt
	}
	if len(data) == 1<<20 {
		return processRecord{}, false, ErrStateCorrupt
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return processRecord{}, false, ErrStateCorrupt
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record processRecord
	if err := decoder.Decode(&record); err != nil {
		return processRecord{}, false, ErrStateCorrupt
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return processRecord{}, false, ErrStateCorrupt
	}
	if err := validateRecord(record); err != nil {
		return processRecord{}, false, ErrStateCorrupt
	}
	return record, true, nil
}

// saveRecord atomically replaces the registration beside its destination.
// saveRecord 在目标文件旁边原子替换进程登记。
func saveRecord(path string, record processRecord) error {
	if err := validateRecord(record); err != nil {
		return ErrStateCorrupt
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return ErrStateCorrupt
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vmmm-process-*.tmp")
	if err != nil {
		return ErrStateCorrupt
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return ErrStateCorrupt
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return ErrStateCorrupt
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return ErrStateCorrupt
	}
	if err := temporary.Close(); err != nil {
		return ErrStateCorrupt
	}
	if err := atomicReplaceFile(temporaryPath, path); err != nil {
		return ErrStateCorrupt
	}
	removeTemporary = false
	return nil
}

// removeRecord removes only the manager-owned process registration.
// removeRecord 只删除管理器拥有的进程登记。
func removeRecord(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// rejectDuplicateJSONKeys rejects duplicate object keys before struct decoding.
// rejectDuplicateJSONKeys 在结构体解码前拒绝重复对象键。
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

// walkJSONValue recursively consumes JSON while checking object keys.
// walkJSONValue 递归消费 JSON，同时检查对象键。
func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || strings.TrimSpace(key) == "" {
				return errors.New("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
