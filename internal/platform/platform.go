// Package platform maps the running installer to the supported release platform and executable names.
// platform 包负责把当前安装器映射到受支持的发行平台及可执行文件名称。
// It is used by release selection and installation paths without performing filesystem or system changes.
// 它供发行版选择与安装路径使用，不执行文件系统或系统状态变更。
package platform

import (
	"fmt"
	"runtime"
)

// Identity contains the release platform ID and local executable paths for one supported target.
// Identity 包含一个受支持目标的发行平台 ID 与本地可执行文件路径。
type Identity struct {
	// PlatformID is the stable ID used to select release assets.
	// PlatformID 是用于选择发行资产的稳定标识。
	PlatformID string

	// ManagerExecutableName is the installed manager filename without a directory component.
	// ManagerExecutableName 是不含目录部分的管理器安装文件名。
	ManagerExecutableName string

	// VMMExecutablePath is the runtime executable path relative to the extracted VMM package root.
	// VMMExecutablePath 是相对于 VMM 解包根目录的运行时可执行文件路径。
	VMMExecutablePath string
}

// Current returns the exact supported identity for the Go runtime OS and architecture.
// Current 按 Go 运行时的操作系统与架构返回精确匹配的受支持身份。
// It returns an error for any runtime pair absent from the signed-release platform contract.
// 若运行时组合不在签名发行契约中，则返回错误。
func Current() (Identity, error) {
	return Resolve(runtime.GOOS, runtime.GOARCH)
}

// Resolve maps one exact Go OS and architecture pair to its release and executable identity.
// Resolve 将一个精确的 Go 操作系统与架构组合映射到发行标识及可执行文件身份。
// It rejects unsupported pairs instead of guessing aliases or selecting a nearby artifact.
// 它拒绝不受支持的组合，不猜测别名，也不选择相近平台的发行资产。
func Resolve(goos string, goarch string) (Identity, error) {
	// These exact pairs mirror the five platform IDs in VMM release assets.
	// 以下精确组合对应 VMM 发行资产中的五个平台 ID。
	switch {
	case goos == "windows" && goarch == "amd64":
		return Identity{
			PlatformID:            "windows-x64",
			ManagerExecutableName: "vmmm.exe",
			VMMExecutablePath:     "bin/vmm-local.exe",
		}, nil
	case goos == "linux" && goarch == "amd64":
		return Identity{
			PlatformID:            "linux-x64",
			ManagerExecutableName: "vmmm",
			VMMExecutablePath:     "bin/vmm-local",
		}, nil
	case goos == "linux" && goarch == "arm64":
		return Identity{
			PlatformID:            "linux-arm64",
			ManagerExecutableName: "vmmm",
			VMMExecutablePath:     "bin/vmm-local",
		}, nil
	case goos == "darwin" && goarch == "amd64":
		return Identity{
			PlatformID:            "macos-intel",
			ManagerExecutableName: "vmmm",
			VMMExecutablePath:     "bin/vmm-local",
		}, nil
	case goos == "darwin" && goarch == "arm64":
		return Identity{
			PlatformID:            "macos-arm64",
			ManagerExecutableName: "vmmm",
			VMMExecutablePath:     "bin/vmm-local",
		}, nil
	default:
		return Identity{}, fmt.Errorf("unsupported platform %s/%s", goos, goarch)
	}
}
