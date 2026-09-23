# Vulcan Memory Mesh Manager

`vmmm` 是 VulcanMemoryMesh OSS 本地版的独立安装器与管理器。它是单文件 Go 程序，与 VMM 分开构建、签名和发布。首次打开 TUI 时，管理器先下载并验证 VMM 完整包，再收集配置，使用包内 `vmm-local config validate` 检查候选配置并提交安装。

**发行状态：**程序和引导脚本模板已实现；Certum Windows 代码签名证书尚未到位，目前没有面向公众的正式 `curl | sh` 或 `irm | iex` 地址。仓库中的 `scripts/install.sh`、`scripts/install.ps1` 含版本和 SHA-256 占位符，直接运行会拒绝；发行流程只会创建并回验 Draft Release。

## 首次安装

1. 选择简体中文或英文，选择 GitHub 官方源、预置的 GitHub HTTPS 代理，或填写自定义 HTTPS 代理前缀。TUI 实时检测可达性；所有下载都要验证固定公钥签发的 Ed25519 清单、文件长度及 SHA-256。
2. 选择 VMM 版本和目录。管理器先下载完整包并验证归档、收据与包内文件，之后才进入配置页。
3. 选择五种存储方式之一，填写相应数据库路径或连接参数；通过快捷向导配置 LLM、Embedding、Rerank 供应商。API Key 与 PostgreSQL/ParadeDB DSN 存入受保护的 `.env`，YAML 只保存环境变量引用。
4. 选择命令行或服务运行方式、服务自启动策略，以及是否将永久安装的 `vmmm` 加入 PATH。高级配置编辑器按当前 VMM 的 `config schema --json` 展示字段，展开已有数组元素的具体路径，支持标量、对象和数组编辑，并保留 YAML 的注释与顺序。长字段列表随选中项滚动；编辑结构化 YAML 时按 `Ctrl+O` 换行，按 `Enter` 暂存字段。敏感字段在列表中脱敏，只接受 `${环境变量名}` 引用；包含敏感子字段的父级集合通过具体子字段或供应商向导修改。
5. 每次修改配置都会使上次校验失效。VMM 的真实配置与规则资产校验通过后，TUI 才允许确认安装。

| 界面选项 | VMM 存储配置 | 数据地址 | 检索方式 |
| --- | --- | --- | --- |
| 原生 | `storage.mode=native` | `sqlite.native.path`、`lancedb.native.path` | SQLite 原生 FTS 与 LanceDB 向量，经混合检索管线融合 |
| VLDB 分离式 | `storage.mode=split` | `storage.local_data_root` | VLDB 关系检索与 LanceDB 向量，经混合检索管线融合 |
| VLDB 控制器 | `storage.mode=controller` | `storage.local_data_root`、控制器参数 | 控制器关系及向量检索，经混合检索管线融合 |
| PostgreSQL | `storage.mode=combined`、`postgres.flavor=standard` | `.env` 中的 PostgreSQL DSN | PostgreSQL 关系及向量索引，按记忆管线融合 |
| ParadeDB | `storage.mode=combined`、`postgres.flavor=paradedb` | `.env` 中的 ParadeDB DSN | `pg_search` BM25 与向量检索融合 |

top-k、RRF、MMR、时间衰减、去重和阈值等由 VMM 配置字段控制，可在高级配置中调整。切换数据库模式或已有数据根不会自动迁移数据，需先停止、备份并按 VMM 文档显式迁移。

## 已安装后的命令

已安装页面的“配置”及 `vmmm config edit` 会先按保存的下载源重新验证并下载当前版本，再编辑候选配置；因此该编辑流程需要联网。候选校验同时包含暂存密钥及已有规则覆盖，正式配置在确认提交前保持不变。既有数据库和日志路径会保留，数据库身份变更仍要求显式迁移。回滚必须选择首页的回滚入口或 `vmmm rollback`，只回滚程序版本，不还原数据库。

配置检查页可编辑 `prompts/`、`pii_rules/`、`noise_rules/` 中的完整文本文件。列表按用户覆盖优先显示，修改系统模板会生成用户覆盖文件；`Ctrl+O` 换行，`Ctrl+U` 清空当前文本，`Enter` 暂存。规则与 YAML、凭据一起交给 VMM 校验，校验失败时不提交。

```text
vmmm                         打开 TUI
vmmm status                  查看安装与运行状态
vmmm start|stop|restart      控制当前运行模式
vmmm enable|disable          切换服务自启动
vmmm service <action>        安装、卸载、控制服务
vmmm service install --user <账户>  Linux/macOS 明确指定服务账户
vmmm config <action>         schema、validate、show-effective、edit
vmmm path enable|disable    管理 vmmm 命令入口
vmmm doctor                 检查状态与配置
vmmm upgrade|rollback       打开 TUI 选择发行包
vmmm uninstall              默认保留配置和数据
```

完整参数见 `vmmm --help`。Linux/macOS 的管理器程序、安装登记与锁由 root 持有；服务使用安装时明确选定的任意本机账户，配置与数据根由该账户持有。两种运行方式均将 `logging.directory` 设为数据根下的 `logs`，使后续转为服务时无需写入管理员持有的程序包；旧安装若缺少此字段，须先在高级配置中设置可写的绝对日志路径。TUI 会要求确认账户，命令行注册服务可用 `--user` 指定。普通用户运行永久安装的 `vmmm` 时，管理器先核验该程序及其父目录，再通过 `/usr/bin/sudo` 打开 TUI 或执行管理命令；首次引导脚本在提权后重新复制并核对固定 SHA-256。选择加入 PATH 后，Unix 在 `/usr/local/bin/vmmm` 建立管理员控制的命令入口。切换命令行/服务方式前会检查配置、程序和数据路径的归属及访问权限。默认卸载保留配置和数据库；删除它们需显式选项。

Windows 如需注册、卸载或控制系统服务，请从“以管理员身份运行”的终端启动 `vmmm`；TUI 会在停止旧实例或提交新文件前检查 UAC 提权状态。仅使用命令行进程模式时可从普通终端运行。

## 开发与发行

开发需要 Go 1.25：`go build -o vmmm.exe ./cmd/vmmm`、`go test ./...`。开发程序的 TUI 首装仍需要可用的正式签名 Release。正式流程从精确标签提交构建五平台单文件资产，为管理器和 VMM 分别使用独立 Ed25519 发布密钥。当前私钥只保存在各仓库 GitHub Actions Secrets；固定公钥与用途见 [发行公钥说明](docs/release-public-keys.md)。

下载源预置 GitHub 官方、`ghproxy.net`、`gh-proxy.org`、`ghfast.top`。代理只传输 GitHub Release URL，不成为发行身份；其可用性随地区和时间变化，TUI 会实时检测。样本与限制见 [下载源调研](docs/DOWNLOAD_SOURCES_CN.md)。完整设计和执行记录见 [安装器实施计划](docs/plan/20260923-01-VMMM_INSTALLER_IMPLEMENTATION.md)。
