//go:build windows

// This file keeps Unix credential ownership requests unavailable on Windows.
// 本文件在 Windows 上明确拒绝 Unix 凭据所有权请求。
package credentials

// validateOwnerTarget rejects Unix ownership on Windows before any credential read.
// validateOwnerTarget 在读取凭据前拒绝 Windows 上的 Unix 所有权请求。
func validateOwnerTarget(_ string, _ Owner) error {
	return ErrOwnerUnsupported
}

// writeAtomicForOwner uses the normal Windows ACL writer unless Unix ownership was requested.
// writeAtomicForOwner 在未请求 Unix 所有权时使用普通 Windows ACL 写入器。
func writeAtomicForOwner(path string, data []byte, owner *Owner) error {
	if owner != nil {
		return ErrOwnerUnsupported
	}
	return writeAtomic(path, data)
}
