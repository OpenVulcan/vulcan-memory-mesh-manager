//go:build windows

// This file retains Windows ACL ownership while sharing service-transfer orchestration with Unix.
// 本文件保留 Windows ACL 归属策略，同时与 Unix 共用服务转换编排。
package install

import "github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"

// TransferServiceRoots leaves Windows ACLs with the existing protected installation adapters.
// TransferServiceRoots 在 Windows 上由现有受保护安装适配器管理 ACL，不执行 Unix 归属调整。
func TransferServiceRoots(_ state.InstallPaths, _ string) (func(bool) error, error) {
	return func(bool) error { return nil }, nil
}
