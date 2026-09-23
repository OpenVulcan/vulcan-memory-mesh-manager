// provider_test_view.go presents the optional network consent and result independently from configuration validity.
// provider_test_view.go 独立于配置有效性展示可选网络确认与结果。
package tui

// ProviderTestSummary identifies the selected purpose and its bounded runtime diagnostic result.
// ProviderTestSummary 标识所选用途及有界运行时诊断结果。
type ProviderTestSummary struct {
	Purpose ProviderPurpose
	Success bool
	Class   string
}

// renderProviderTest explains paid failover attempts and defaults the cursor to returning without a request.
// renderProviderTest 说明可能收费的故障转移尝试，默认光标选择返回且不发请求。
func (m *Model) renderProviderTest() []string {
	lines := []string{
		m.label("可选供应商在线测试", "Optional online provider test"),
		m.label("将使用候选凭据发送固定测试内容，可能产生费用。", "Sends fixed test content using candidate credentials; charges may apply."),
		m.label("最多等待 20 秒；密钥故障转移可能发出多次请求。", "Waits up to 20 seconds; key failover may send multiple requests."),
		m.label("只测试所选用途首条路由，不写数据库；结果不代表全部路由可用。", "Tests only the first route for the selected purpose, without database writes; other routes are untested."),
		m.option(0, m.label("返回，不发送请求", "Back without sending")),
		m.option(1, m.label("确认发送 LLM 测试", "Confirm LLM test")),
		m.option(2, m.label("确认发送 embedding 测试", "Confirm embedding test")),
		m.option(3, m.label("确认发送重排测试", "Confirm rerank test")),
	}
	if m.providerTest != nil {
		lines = append(lines, m.providerTestText(*m.providerTest))
	}
	return lines
}

// providerTestText translates only the finite protocol classes; configuration values and upstream text are never used here.
// providerTestText 只翻译有限协议类别；此处不使用配置值或上游文本。
func (m *Model) providerTestText(result ProviderTestSummary) string {
	label := m.label("未知结果", "Unknown result")
	switch result.Class {
	case "ok":
		label = m.label("测试通过", "Passed")
	case "configuration":
		label = m.label("配置或所选路由不可用", "Configuration or route unavailable")
	case "request-failed":
		label = m.label("网络、认证或供应商请求失败", "Network, authentication or provider request failed")
	case "invalid-response":
		label = m.label("响应内容或向量维度不符合要求", "Unexpected response or embedding dimension")
	case "timeout":
		label = m.label("测试超时", "Timed out")
	case "cancelled":
		label = m.label("测试已取消", "Cancelled")
	}
	return string(result.Purpose) + ": " + label
}
