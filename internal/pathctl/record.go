// This file persists complete pathctl records without weakening the installation state schema.
// 本文件持久化完整 pathctl 记录，不降低安装状态 schema 的安全约束。
// The record keeps platform metadata needed to reverse profile and link changes after restart.
// 该记录保存重启后撤销 profile 与链接变更所需的平台元数据。
package pathctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// maxRecordBytes bounds parsing work for the manager-owned path record.
	// maxRecordBytes 限制管理器路径记录的解析工作量。
	maxRecordBytes int64 = 1 << 20
)

// SaveRecord validates and atomically persists a complete path integration record.
// SaveRecord 校验完整路径集成记录，并以原子方式持久化。
func SaveRecord(filePath string, record Record) error {
	if err := validateRecordFilePath(filePath); err != nil {
		return fmt.Errorf("save path record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return fmt.Errorf("save path record: %w", err)
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal path record: %w", err)
	}
	payload = append(payload, '\n')

	parent := filepath.Dir(filepath.Clean(filePath))
	temporary, err := os.CreateTemp(parent, ".path-record.tmp-*")
	if err != nil {
		return fmt.Errorf("create path record temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set path record permissions: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write path record temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync path record temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close path record temporary file: %w", err)
	}
	if err := replaceRecord(temporaryPath, filepath.Clean(filePath)); err != nil {
		return fmt.Errorf("replace path record: %w", err)
	}
	removeTemporary = false
	return nil
}

// LoadRecord reads and strictly validates a complete path integration record.
// LoadRecord 读取并严格校验完整路径集成记录。
func LoadRecord(filePath string) (Record, error) {
	if err := validateRecordFilePath(filePath); err != nil {
		return Record{}, fmt.Errorf("load path record: %w", err)
	}
	if err := validateRecordPermissions(filePath); err != nil {
		return Record{}, fmt.Errorf("load path record permissions: %w", err)
	}
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return Record{}, fmt.Errorf("open path record: %w", err)
	}
	defer file.Close()
	data, err := readRecordBounded(file)
	if err != nil {
		return Record{}, fmt.Errorf("read path record: %w", err)
	}
	record, err := decodeRecordStrict(data)
	if err != nil {
		return Record{}, fmt.Errorf("decode path record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return Record{}, fmt.Errorf("validate path record: %w", err)
	}
	return record, nil
}

// validateRecordFilePath rejects symlinked records and symlinked parent directories.
// validateRecordFilePath 拒绝符号链接记录文件和符号链接父目录。
func validateRecordFilePath(filePath string) error {
	if err := validateAbsoluteText("record_file", filePath); err != nil {
		return err
	}
	cleanPath := filepath.Clean(filePath)
	if cleanPath == "." || filepath.Base(cleanPath) == "." {
		return errors.New("record_file must name a file")
	}
	parent := filepath.Dir(cleanPath)
	if err := validateRecordDirectory(parent); err != nil {
		return err
	}
	info, err := os.Lstat(cleanPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect record file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("record_file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("record_file must be a regular file")
	}
	return nil
}

// validateRecordDirectory ensures the parent is a real directory with no symlink traversal.
// validateRecordDirectory 确保父目录是真实目录且路径中没有符号链接穿越。
func validateRecordDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect record directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("record directory must not be a symlink")
	}
	if !info.IsDir() {
		return errors.New("record parent must be a directory")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return fmt.Errorf("resolve record directory: %w", err)
	}
	if !sameRecordPath(resolved, filepath.Clean(directory)) {
		return errors.New("record directory path must not traverse a symlink")
	}
	return nil
}

// sameRecordPath compares resolved paths using Windows case rules when applicable.
// sameRecordPath 在 Windows 使用大小写不敏感规则比较解析后的路径。
func sameRecordPath(left string, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if filepath.VolumeName(left) != "" || filepath.VolumeName(right) != "" {
		return equalFoldPath(left, right)
	}
	return left == right
}

// equalFoldPath compares Windows path spellings without changing stored paths.
// equalFoldPath 比较 Windows 路径拼写但不改动储存的路径。
func equalFoldPath(left string, right string) bool {
	if filepath.Separator == '\\' {
		return strings.EqualFold(left, right)
	}
	return left == right
}

// readRecordBounded reads one record plus one byte to enforce a hard size limit.
// readRecordBounded 多读取一个字节，以执行严格记录大小上限。
func readRecordBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRecordBytes {
		return nil, fmt.Errorf("path record exceeds %d bytes", maxRecordBytes)
	}
	return data, nil
}

// decodeRecordStrict rejects duplicate keys, unknown fields, and trailing JSON values.
// decodeRecordStrict 拒绝重复键、未知字段和尾随 JSON 值。
func decodeRecordStrict(data []byte) (Record, error) {
	if err := rejectDuplicateRecordKeys(data); err != nil {
		return Record{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Record{}, errors.New("path record contains multiple JSON values")
		}
		return Record{}, fmt.Errorf("trailing JSON is invalid: %w", err)
	}
	return record, nil
}

// rejectDuplicateRecordKeys walks every JSON object before struct decoding.
// rejectDuplicateRecordKeys 在结构体解码前遍历每个 JSON 对象并拒绝重复键。
func rejectDuplicateRecordKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkRecordJSON(decoder, "$", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("path record contains multiple top-level JSON values")
		}
		return fmt.Errorf("JSON after path record is invalid: %w", err)
	}
	return nil
}

// walkRecordJSON recursively consumes one JSON value and tracks object keys.
// walkRecordJSON 递归消费一个 JSON 值并跟踪对象键。
func walkRecordJSON(decoder *json.Decoder, location string, depth int) error {
	if depth > 128 {
		return errors.New("path record JSON nesting exceeds 128 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
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
			if !ok {
				return fmt.Errorf("JSON object key at %s is not a string", location)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q at %s", key, location)
			}
			seen[key] = struct{}{}
			if err := walkRecordJSON(decoder, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("JSON object at %s is not closed", location)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walkRecordJSON(decoder, fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("JSON array at %s is not closed", location)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, location)
	}
	return nil
}
