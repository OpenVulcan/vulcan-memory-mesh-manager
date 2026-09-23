//go:build windows

// This file keeps Windows service invocation unchanged because SCM owns elevation and account policy.
// 本文件保持 Windows 服务调用不变，因为 SCM 负责提权和账户策略。
// It belongs to the service adapter and deliberately never inserts a Unix sudo command.
// 它属于服务适配层，明确不会插入 Unix sudo 命令。
package service

// preparePrivilegedCommand leaves the VMM command vector unchanged on Windows.
// preparePrivilegedCommand 在 Windows 上原样返回 VMM 命令参数数组。
func preparePrivilegedCommand(binaryPath string, args []string, _ bool) (string, []string, bool, error) {
	return binaryPath, args, false, nil
}
