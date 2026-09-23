// This file checks installation completeness without storing recovery journals or changing files.
// 本文件检查安装完整性，不保存恢复日志，也不修改文件。
package install

import (
	"os"
	"path/filepath"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// FilesIntact verifies registered program bytes and the required user configuration before any runtime command is launched.
// FilesIntact 在启动任何运行时命令前核对登记的程序内容与必要用户配置；返回稳定失败类别，不暴露配置值。
func FilesIntact(installed state.State) string {
	if err := installed.Validate(); err != nil {
		return "invalid-registration"
	}
	if len(installed.ManagedFiles) == 0 {
		return "missing-program-files"
	}
	identity, err := platform.Current()
	if err != nil || installed.VMM.Platform != identity.PlatformID {
		return "invalid-registration"
	}
	foundExecutable := false
	for _, item := range installed.ManagedFiles {
		if item.Path == identity.VMMExecutablePath {
			foundExecutable = true
		}
		target, err := safeProgramPath(installed.Paths.ProgramRoot, item.Path)
		if err != nil {
			return "unsafe-program-path"
		}
		if err := validateDirectoryChain(installed.Paths.ProgramRoot, filepath.Dir(target)); err != nil {
			return "unsafe-program-path"
		}
		info, err := os.Lstat(target)
		if err != nil {
			return "missing-program-files"
		}
		if isUnsafePathEntry(target, info) || !info.Mode().IsRegular() {
			return "unsafe-program-path"
		}
		matches, err := fileMatches(target, item.SHA256, item.Size)
		if err != nil || !matches {
			return "changed-program-files"
		}
	}
	if !foundExecutable {
		return "missing-program-files"
	}
	configPath, err := safeConfigPath(installed.Paths.ConfigRoot, UserConfigFileName)
	if err != nil {
		return "missing-configuration"
	}
	info, err := os.Lstat(configPath)
	if err != nil || isUnsafePathEntry(configPath, info) || !info.Mode().IsRegular() {
		return "missing-configuration"
	}
	return ""
}

// HasProgramRemnants reports a nonempty selected program directory without treating it as a completed installation.
// HasProgramRemnants 检测所选程序目录中的遗留文件，不将其视为已完成安装。
func HasProgramRemnants(programRoot string) bool {
	info, err := os.Lstat(programRoot)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil || isUnsafePathEntry(programRoot, info) || !info.IsDir() {
		return true
	}
	entries, err := os.ReadDir(programRoot)
	return err != nil || len(entries) != 0
}
