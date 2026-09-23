// This file checks saved configuration through the authoritative runtime and records only successful check timestamps.
// 本文件属于控制器层，通过权威运行时检查已保存配置，仅记录检查通过时间。
package controller

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// ValidateInstalled checks the exact registered root under the installation lock and preserves historical success on validation failure.
// ValidateInstalled 在安装锁内检查精确登记配置根；失败保留历史通过时间，返回权威结果或安全错误，不改变完成标记。
func (c *Controller) ValidateInstalled(ctx context.Context) (configbridge.ValidationResult, error) {
	if c == nil || ctx == nil {
		return configbridge.ValidationResult{}, errors.New("configuration controller is unavailable")
	}
	releaseLock, err := install.LockInstallation(ctx, c.options.StatePath)
	if err != nil {
		return configbridge.ValidationResult{}, err
	}
	defer releaseLock()
	installed, err := c.requireState()
	if err != nil {
		return configbridge.ValidationResult{}, err
	}
	if !installed.InstallationComplete {
		return configbridge.ValidationResult{}, errors.New("VMM installation is incomplete")
	}
	if install.FilesIntact(installed) != "" {
		return configbridge.ValidationResult{}, errors.New("VMM installation is incomplete")
	}
	binary := filepath.Join(installed.Paths.ProgramRoot, filepath.FromSlash(c.identity.VMMExecutablePath))
	result, err := c.options.Validate(ctx, binary, installed.Paths.ConfigRoot)
	if err != nil {
		return configbridge.ValidationResult{}, errors.New("VMM configuration validation could not be completed")
	}
	if err := ctx.Err(); err != nil {
		return configbridge.ValidationResult{}, err
	}
	if result.Valid {
		installed.ConfigValidatedAt = c.options.Clock().UTC().Format(time.RFC3339Nano)
		if err := state.Save(c.options.StatePath, installed); err != nil {
			return configbridge.ValidationResult{}, errors.New("configuration check time could not be saved")
		}
	}
	return result, nil
}

// validateSaved emits a dedicated result and refreshed snapshot; invalid configuration is a completed check, not an installation failure.
// validateSaved 发出独立检查结果及刷新快照；配置无效表示检查得到否定结果，不将其误报为安装失败。
func (c *Controller) validateSaved(ctx context.Context, events chan<- tui.OperationEvent) error {
	result, err := c.ValidateInstalled(ctx)
	if err != nil {
		return err
	}
	snapshot, err := c.snapshot(ctx)
	if err != nil {
		return err
	}
	summary := validationSummary(result)
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, Validation: &summary, Snapshot: &snapshot})
	return nil
}
