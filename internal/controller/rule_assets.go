// This file exposes shipped and user-overridden rule files to the controller's configuration editor.
// 本文件将随包规则及用户覆盖规则接入控制器的配置编辑器。
package controller

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// maxRuleFileBytes bounds individual text assets before rendering or staging them.
// maxRuleFileBytes 限制渲染及暂存前的单个文本规则文件大小。
const maxRuleFileBytes = 1 << 20

// validRuleAssetPath accepts only canonical relative files in the three VMM override namespaces.
// validRuleAssetPath 仅接受 VMM 三类规则覆盖命名空间内的规范相对文件路径。
func validRuleAssetPath(relative string) bool {
	if !fs.ValidPath(relative) || strings.ContainsAny(relative, "\\:") || path.Clean(relative) != relative {
		return false
	}
	for _, prefix := range []string{"prompts/", "pii_rules/", "noise_rules/"} {
		if strings.HasPrefix(relative, prefix) {
			return true
		}
	}
	return false
}

// readRuleAssets merges system and user text assets through pinned roots; later user files override identical system paths.
// readRuleAssets 使用固定根目录句柄合并系统与用户文本规则，用户文件覆盖同路径系统文件。
func readRuleAssets(systemRoot, configRoot string) ([]tui.ConfigField, error) {
	assets := make(map[string]tui.ConfigField)
	for _, directory := range []string{systemRoot, configRoot} {
		root, err := os.OpenRoot(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		err = collectRuleAssets(root, assets)
		_ = root.Close()
		if err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(assets))
	for name := range assets {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]tui.ConfigField, 0, len(names))
	for _, name := range names {
		fields = append(fields, assets[name])
	}
	return fields, nil
}

// collectRuleAssets reads only regular UTF-8 files under known rule directories and caps the combined editor payload.
// collectRuleAssets 仅读取已知规则目录下的普通 UTF-8 文件，并限制编辑器总载荷。
func collectRuleAssets(root *os.Root, assets map[string]tui.ConfigField) error {
	for _, namespace := range []string{"prompts", "pii_rules", "noise_rules"} {
		if _, err := root.Lstat(namespace); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		err := fs.WalkDir(root.FS(), namespace, func(relative string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !validRuleAssetPath(relative) || !entry.Type().IsRegular() {
				return errors.New("rule asset must be a regular relative file")
			}
			file, err := root.Open(relative)
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(file, maxRuleFileBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(data) > maxRuleFileBytes || !utf8.Valid(data) {
				return errors.New("rule asset is not a bounded UTF-8 text file")
			}
			assets[relative] = tui.ConfigField{Path: relative, Type: "string", Value: string(data), Editable: true, RuleAsset: true}
			var total int64
			for _, asset := range assets {
				total += int64(len(asset.Value))
			}
			if total > maxConfigBytes || len(assets) > 4096 {
				return errors.New("rule asset tree exceeds editor limits")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
