# Release public keys / 发行公钥

VMMM and VMM use separate Ed25519 keys for detached release manifest signatures. Only the public keys appear here and in the manager binary. The private seeds are held by the corresponding repositories' GitHub Actions Secrets.

VMMM 与 VMM 分别使用 Ed25519 密钥签署独立的发行清单。本文和管理器二进制仅包含公钥；私钥种子仅保存在各自仓库的 GitHub Actions Secrets 中。

| Product / 产品 | Key ID / 密钥标识 | Base64 public key / 公钥 |
| --- | --- | --- |
| VMMM | `vmmm-2026-09-23-01` | `S4zmW0F/BJA7MbvupEdD1jYuaA2tUlBfFRsuDBVjge0=` |
| VMM | `vmm-2026-09-23-01` | `h2906GgOkZSmkYGWy3tV6/sH0+zyCcnhTZKjKx06cpM=` |

The VMMM repository uses `VMMM_RELEASE_ED25519_PRIVATE_KEY` and `VMMM_RELEASE_ED25519_KEY_ID`. The VMM repository uses `VMM_RELEASE_ED25519_PRIVATE_KEY` and `VMM_RELEASE_ED25519_KEY_ID`. Both workflows must reject missing secrets and verify every signature against the committed public key before creating a release draft.

VMMM 仓库使用 `VMMM_RELEASE_ED25519_PRIVATE_KEY` 与 `VMMM_RELEASE_ED25519_KEY_ID`；VMM 仓库使用 `VMM_RELEASE_ED25519_PRIVATE_KEY` 与 `VMM_RELEASE_ED25519_KEY_ID`。两个工作流均须在缺少 Secret 时失败，并在创建发行草稿前用已提交的公钥验签。

## 固定公钥的轮换与吊销

当前信任根编译在 `internal/trust/keys.go` 中，清单和下载代理不能添加信任根。轮换由维护者通过代码评审与新管理器发行完成；不从网络下载未经现有信任根确认的新公钥。

1. 为需要轮换的产品创建新的独立 Ed25519 密钥及唯一密钥标识，私钥仍只保存到该产品的 GitHub Actions Secrets。先准备并评审公钥改动，再协调替换 Secret，防止公钥与 Secret 不一致；工作流会拒绝这种不一致。
2. 同步更新管理器的该产品固定公钥、两个仓库中对应产品的发行验签配置，以及本文公钥表。VMM 密钥改变时，也必须发行含新 VMM 信任根的管理器；旧管理器会明确拒绝新密钥。
3. 在测试密钥上验证新签名被新信任根接受、旧签名被移除旧公钥的信任根拒绝、两个产品不能交叉使用密钥。再完成新管理器五平台发行与固定摘要引导脚本生成，不改写已发布版本的资产。
4. 用户通过受信官方入口重新取得新引导脚本或新管理器，并独立核对官方完整 SHA-256。仅重新下载旧版管理器不会更新其内置公钥。不得依赖可能已经泄露的旧签名密钥来认证紧急替换。

若怀疑私钥泄露，应先停止对应发行流程、撤销或替换该仓库 Secret，调查受影响发行物，再按上述流程移除旧公钥并发布新管理器和官方通知。撤销 GitHub Secret 只能阻止工作流继续使用它，不能使攻击者持有的副本失效。

**吊销边界：**离线旧管理器仍保留旧公钥，无法自动得知吊销；当前没有在线吊销服务。必须更新管理器才能移除旧信任，固定摘要引导脚本也必须通过受信官方入口更新。撤下资产和发布通知不能被描述为已经远程撤销所有旧安装。Certum 的 Windows 代码签名证书与此清单签名机制分别管理。
