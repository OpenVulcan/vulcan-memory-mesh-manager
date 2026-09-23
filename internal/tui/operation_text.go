// This file localizes manager-owned controller messages at rendering time.
// 本文件在渲染时翻译管理器自身的控制器消息，切换语言无需重新执行操作。
package tui

// operationChinese covers the exact controller messages and stable lifecycle states used by this build.
// operationChinese 覆盖本版本控制器使用的精确消息与稳定生命周期状态。
// Runtime diagnostics and configuration values are preserved verbatim because their text is owned by VMM or the user.
// 运行时诊断与配置值由 VMM 或用户拥有，保持原文以避免改变其含义。
var operationChinese = map[string]string{
	"test-provider": "测试供应商",
	"Service program files are damaged; stop the service with the operating system and restore the verified package at the original program root before retrying": "服务程序文件已损坏；请通过操作系统停止服务，将已验证的安装包恢复到原程序目录后重试",
	"unverified":                                         "未验证",
	"not-installed":                                      "尚未注册",
	"Rule assets loaded":                                 "规则文件已加载",
	"Configuration fields loaded":                        "配置字段已加载",
	"Provider catalog loaded":                            "供应商目录已加载",
	"Operation cancelled":                                "操作已取消",
	"Operation completed":                                "操作已完成",
	"Operation failed":                                   "操作失败",
	"No verified VMM package is staged":                  "尚未暂存经过验证的 VMM 安装包",
	"Foreground process control is unavailable":          "命令行进程控制不可用",
	"Manager PATH integration cannot be safely reversed": "无法安全撤销管理器的 PATH 设置",
	"VMM runtime did not become healthy; run vmmm doctor for diagnostics":           "VMM 未达到健康状态；请运行 vmmm doctor 查看诊断",
	"Checking selected download source":                                             "正在检查所选下载源",
	"Source passed download checks":                                                 "下载源已通过检查",
	"Resolving authenticated VMM release":                                           "正在查找已认证的 VMM 发行版本",
	"Authenticated VMM release is available":                                        "已认证的 VMM 发行版本可用",
	"Verifying selected VMM release":                                                "正在验证所选 VMM 发行版本",
	"Downloading and verifying VMM package":                                         "正在下载并验证 VMM 安装包",
	"Verifying VMM package contents":                                                "正在验证 VMM 安装包内容",
	"VMM package is staged and verified":                                            "VMM 安装包已暂存并通过验证",
	"Stopping the running VMM service before package replacement":                   "正在停止 VMM 服务，以便替换程序包",
	"Removing the old VMM service registration before changing its executable path": "正在注销旧 VMM 服务，以便更改程序路径",
	"Stopping the running VMM process before package replacement":                   "正在停止 VMM 进程，以便替换程序包",
	"Restoring the previously running VMM runtime":                                  "正在恢复先前运行的 VMM 实例",
	"Validating candidate configuration with VMM":                                   "正在使用 VMM 校验候选配置",
	"VMM files prepared; reconciling runtime and PATH":                              "VMM 文件已准备，正在应用运行方式和 PATH 设置",
	"VMM installation is ready":                                                     "VMM 安装已完成",
	"Running authoritative VMM configuration validation":                            "正在执行 VMM 权威配置校验",
	"VMM configuration is valid":                                                    "VMM 配置有效",
	"VMM configuration is invalid":                                                  "VMM 配置无效",
	"Lifecycle action completed":                                                    "运行管理操作已完成",
	"PATH choice applied":                                                           "PATH 设置已应用",
	"VMM program files were removed":                                                "VMM 程序文件已移除",
	"Installation status refreshed":                                                 "安装状态已刷新",
	"probe-source":                                                                  "检查下载源",
	"fetch-versions":                                                                "查询版本",
	"discover-release":                                                              "验证发行版",
	"download":                                                                      "下载",
	"extract":                                                                       "解包",
	"stage-package":                                                                 "暂存安装包",
	"stop-runtime":                                                                  "停止实例",
	"restore-runtime":                                                               "恢复实例",
	"validate-config":                                                               "校验配置",
	"install":                                                                       "安装",
	"service":                                                                       "运行管理",
	"path":                                                                          "设置 PATH",
	"uninstall":                                                                     "卸载",
	"refresh":                                                                       "刷新",
	"not-registered":                                                                "未注册",
	"foreground":                                                                    "命令行模式",
	"running":                                                                       "运行中",
	"stopped":                                                                       "已停止",
}

// operationText translates only known manager-owned values, retaining unknown runtime output unchanged.
// operationText 只翻译管理器拥有的已知文本，未知运行时输出保持原文。
func (m *Model) operationText(value string) string {
	if m.language == LanguageChinese {
		if translated, found := operationChinese[value]; found {
			return translated
		}
	}
	return value
}
