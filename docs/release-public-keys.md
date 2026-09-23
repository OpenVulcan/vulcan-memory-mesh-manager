# Release public keys / 发行公钥

VMMM and VMM use separate Ed25519 keys for detached release manifest signatures. Only the public keys appear here and in the manager binary. The private seeds are held by the corresponding repositories' GitHub Actions Secrets.

VMMM 与 VMM 分别使用 Ed25519 密钥签署独立的发行清单。本文和管理器二进制仅包含公钥；私钥种子仅保存在各自仓库的 GitHub Actions Secrets 中。

| Product / 产品 | Key ID / 密钥标识 | Base64 public key / 公钥 |
| --- | --- | --- |
| VMMM | `vmmm-2026-09-23-01` | `S4zmW0F/BJA7MbvupEdD1jYuaA2tUlBfFRsuDBVjge0=` |
| VMM | `vmm-2026-09-23-01` | `h2906GgOkZSmkYGWy3tV6/sH0+zyCcnhTZKjKx06cpM=` |

The VMMM repository uses `VMMM_RELEASE_ED25519_PRIVATE_KEY` and `VMMM_RELEASE_ED25519_KEY_ID`. The VMM repository uses `VMM_RELEASE_ED25519_PRIVATE_KEY` and `VMM_RELEASE_ED25519_KEY_ID`. Both workflows must reject missing secrets and verify every signature against the committed public key before creating a release draft.

VMMM 仓库使用 `VMMM_RELEASE_ED25519_PRIVATE_KEY` 与 `VMMM_RELEASE_ED25519_KEY_ID`；VMM 仓库使用 `VMM_RELEASE_ED25519_PRIVATE_KEY` 与 `VMM_RELEASE_ED25519_KEY_ID`。两个工作流均须在缺少 Secret 时失败，并在创建发行草稿前用已提交的公钥验签。
