// provider_test_operation.go tests a verified candidate with staged credentials while leaving the installation untouched.
// provider_test_operation.go 使用已验证候选配置及暂存凭据测试供应商，保持安装内容不变。
package controller

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// testProvider verifies request consent, builds an isolated candidate, and emits an online result independently of static validation.
// testProvider 验证请求确认、构造隔离候选配置，并独立于静态校验发送在线结果。
func (c *Controller) testProvider(ctx context.Context, request tui.OperationRequest, events chan<- tui.OperationEvent) error {
	if !request.ConfirmProviderNetwork {
		return errors.New("Provider test requires explicit confirmation")
	}
	if request.ProviderPurpose != tui.ProviderPurposeLLM && request.ProviderPurpose != tui.ProviderPurposeEmbedding && request.ProviderPurpose != tui.ProviderPurposeRerank {
		return errors.New("Provider test selection is invalid")
	}
	staged, err := c.matchStaged(request.Plan)
	if err != nil {
		return err
	}
	verified, cleanup, err := c.reverifyStagedPackage(ctx, staged)
	if err != nil {
		return errors.New("staged VMM package could not be reverified")
	}
	defer cleanup()
	files, err := c.buildConfigFiles(ctx, request.Plan, verified.Root)
	if err != nil {
		return err
	}
	candidate, removeCandidate, err := install.PrepareCandidateConfig(request.Plan.ConfigRoot, c.options.CacheRoot, files)
	if err != nil {
		return errors.New("could not create candidate configuration directory")
	}
	defer removeCandidate()
	// Never persist a test's credentials or apply service ownership to the installed tree.
	// 不持久化测试凭据，也不修改安装目录的服务归属。
	plan := request.Plan
	plan.ConfigRoot = candidate
	plan.Providers.CredentialPath = filepath.Join(candidate, ".env")
	plan.StorageSettings.PostgreSQLCredentialPath = filepath.Join(candidate, ".env")
	plan.ServiceMode = tui.ServiceModeForeground
	if _, err := c.applyCredentialUpdates(plan); err != nil {
		return err
	}
	binary := filepath.Join(verified.Root, filepath.FromSlash(c.identity.VMMExecutablePath))
	validation, err := c.options.Validate(ctx, binary, candidate)
	if err != nil || !validation.Valid {
		return errors.New("VMM configuration is invalid")
	}
	result, err := c.options.TestProvider(ctx, binary, candidate, string(request.ProviderPurpose), 0, true)
	if err != nil {
		return errors.New("Provider test could not be completed")
	}
	summary := tui.ProviderTestSummary{Purpose: request.ProviderPurpose, Success: result.Success, Class: result.Class}
	c.emit(events, tui.OperationEvent{Kind: tui.OperationEventProgress, ProviderTest: &summary})
	if !result.Success {
		return errors.New("Provider request failed; static configuration validity is unchanged")
	}
	return nil
}
