# VMMM 独立安装与配置管理器实施方案

状态：实施中。用户已明确要求完成本方案，并在实现后循环审核与修复，直到连续五轮审核没有发现问题；本文是实现与验收基线。

## 一、任务目标与边界

在独立仓库 `vulcan-memory-mesh-manager` 开发 `vmmm`。用户通过 Windows PowerShell 或 POSIX shell 引导脚本下载并启动管理器；管理器再下载匹配平台的 VMM 正式发行包，以交互式 TUI 完成首次安装、完整配置、校验、启动方式选择，并在后续提供升级、修复、服务管理、配置管理和卸载。无交互终端时提供明确报错与可脚本化命令，不在管道中悄悄执行安装。

VMMM 管理 VMM OSS 本地版，不承载 VMM 业务逻辑，不引入 SaaS 路径或 Postgres 专用存储回归。所有配置语义、模式合法性和最终校验以 VMM 版本自身为准；VMMM 保存用户意图、生成覆盖层并调用其校验能力。

## 二、当前源码事实与配置清单

分析基线：`VulcanMemoryMesh` 提交 `72ea960ad2b9b95b126d3ac84ba7f0dd2e9bf35e`，工作区无未提交变更。以下是源码事实，不代表安装器现已具备这些能力。

### 2.1 配置位置与加载语义

| 层次 | 当前来源 | 作用与约束 |
| --- | --- | --- |
| 系统底座 | 可执行文件旁 `../configs/base.yaml` | 正式包必须保持 `bin/` 与 `configs/` 的相对结构；缺失时正式可执行文件启动失败。 |
| 随包覆盖 | `../configs/config.yaml` | 若存在则在底座后加载。当前受版本控制的文件是 DeepSeek/Bailian/combined 本地测试覆盖，不适合作为安装器的生产默认值。 |
| 用户覆盖 | 默认 `~/.vmm/config.yaml`，或 `-config` 指定目录或 YAML 文件 | 最后覆盖前两层；`-config` 文件路径同时决定 prompts、PII、noise 覆盖根。主配置只接受 YAML。 |
| 环境变量 | 每层配置引用的 `${NAME}`，各层相邻 `.env`，进程环境，以及受支持的 `VMM_*` 覆盖 | 先解析引用并加载 `.env`，再逐层展开和合并，最后应用允许的环境覆盖。需避免把密钥写进诊断日志。 |
| 规则资产 | `configs/prompts/`、`pii_rules/`、`noise_rules/` 及用户覆盖目录 | 系统层与用户层都属于配置的一部分；不能仅编辑一份 YAML 就宣称覆盖全部配置。 |

`internal/config/config_load.go` 使用严格字段解码，拒绝未知字段；顶层 `x-*` 只用于 YAML 锚点辅助块；AI key 与节点在分层覆盖时有专门的重置语义。配置经过 `Normalize`、`Validate` 后才进入运行时。安装器不得自行模拟这套合并算法作为最终权威。

### 2.2 顶层配置域

`internal/config/config.go` 的运行时 `Config` 声明如下。高级编辑器须能覆盖所有已声明字段，包括结构体内的数组、映射、可选值和新增字段；表单只负责常用项。每个版本以 VMM 导出的模式描述驱动表单，而不是在 VMMM 中复制一套永久固定的字段表。

| 配置域 | 主要内容 | 安装器界面 |
| --- | --- | --- |
| `grpc` | 监听、消息大小、各 RPC 超时、keepalive | 网络与监听 |
| `management` | 可选管理监听、令牌、分页和超时；当前 `base.yaml` 未显式列出该段 | 高级网络与安全 |
| `logging` | 等级、格式、载荷调试、输出保护与加密密钥 | 日志与诊断 |
| `pii`、`noise` | 默认语言、噪声准入与语义阈值 | 隐私与过滤 |
| `prompts` | 提示词包选择 | 语言与提示词 |
| `storage` | 存储拓扑和 combined provider | 存储选择 |
| `sqlite`、`lancedb`、`controller`、`postgres` | 各模式的数据地址、动态库、连接、超时、分词和索引设置 | 存储高级设置 |
| `maintenance_tool` | 离线维护批量和 PostgreSQL 超时 | 高级维护 |
| `llm` | 多路由、六场景权重、供应商、模型、密钥池、配额、参数、容灾 | 供应商快捷配置与高级路由 |
| `embedding` | 单供应商单模型、维度、批量、密钥池和容灾 | 向量模型配置 |
| `rerank` | 可选多路由、优先级、模型、密钥池、超时 | 重排模型配置 |
| `vector`、`relational` | 分离/原生/controller 模式的后端标识 | 存储兼容性展示 |
| `post_action`、`pre_check` | 入站模式、分析触发、召回窗口与超时 | 处理流程 |
| `memory_pipeline` | 混合检索、词法 TopK、RRF、MMR、去重、Weibull 衰减 | 检索算法 |
| `retention`、`memory_replace_scope` | 冷数据治理、回收、保护阈值、替换范围 | 数据生命周期 |

供应商现有可选标识由 VMM 校验器确定：LLM/embedding 支持 `openai`、`openai_native`、`openai_go`、`google_ai_studio`、`openrouter`；rerank 的合法供应商须读取对应版本的路由校验器与模板。`llm.routes` 至少一条；`embedding` 必须有 provider、模型、维度、批量和有效密钥节点；启用 `rerank` 时必须有路由。快捷模板只能给出可验证的字段与示例，不能猜测用户模型维度、额度或 API 能力。

### 2.3 存储与检索的准确映射

| TUI 用户选项 | 实际配置 | 数据存放与依赖 | 词法 / 向量召回 |
| --- | --- | --- | --- |
| 本地原生 | `storage.mode=native`；`relational.provider=sqlite`；`vector.provider=lancedb` | 独立 SQLite 文件及 LanceDB 目录；SQLite 用原生适配器，LanceDB 需随包动态库；`sqlite.native.path`、`lancedb.native.path` 可指定路径。 | SQLite FTS5/BM25，`gse` 或 `unicode61`；LanceDB 向量搜索；混合开启后应用层 RRF。 |
| 本地分离 | `storage.mode=split`；SQLite + LanceDB | 随包 VLDB SQLite/LanceDB FFI 动态库；`sqlite.address`、`lancedb.address` 是兼容字段，当前 split 忽略。数据默认在包根 `database/`。 | VLDB SQLite 词法搜索与 LanceDB 向量搜索；混合开启后应用层 RRF。不得擅自把它描述成 native FTS5。 |
| VLDB 控制器 | `storage.mode=controller`；SQLite + LanceDB | `vldb-controller` 拥有数据库句柄；loopback endpoint；可自动启动受管进程，亦可配置 controller service 模式。 | 通过控制器提供 SQLite/LanceDB 检索接口；上层混合与重排按 VMM 配置执行。 |
| PostgreSQL | `storage.mode=combined`；`storage.combined_provider=postgres`；`postgres.flavor=standard` | 一套 PostgreSQL combined store，需 DSN 与 pgvector/pg_trgm 所需扩展。 | pgvector 向量与 trigram/ILIKE 词法；混合开启时 SQL 内按 RRF 融合，再进入应用层后处理。 |
| ParadeDB | 与 PostgreSQL 同为 `combined/postgres`，另设 `postgres.flavor=paradedb` | PostgreSQL combined store，需 pgvector 与 ParadeDB `pg_search` 能力及相应索引。 | pgvector 向量与 ParadeDB BM25 词法；混合开启时 SQL 内按 RRF 融合，再进入应用层后处理。 |

`memory_pipeline.hybrid_enabled` 决定是否进入混合召回；`rerank.enabled`、`mmr_enabled`、Weibull 等为可选后处理，不能把这些开关误写为数据库自带算法。`embedding.dimension`、模型及参数变更可能与已有索引身份不匹配，安装器必须报告重建或迁移要求，禁止静默切换。数据库模式切换也不是简单改 YAML；需要 VMM 官方迁移命令和校验结果。

### 2.4 发行包与服务现状

VMM `v0.1.0` 正式发行脚本生成 Windows x64 ZIP，以及 Linux x64/ARM64、macOS Intel/ARM64 的 tar.gz；包内含 `bin/vmm-local`、`vmm-migrate`、`vmm-pii-tester`、`configs/`、`libs/`、`release-manifest.json`，外部发行资产附 `.json` 与 `SHA256SUMS`。`release-manifest.json` 记录逐文件摘要。当前已发布包采用 `native` 构建 profile，未随包提供 controller 与 legacy 两套库；不能把该版本直接作为支持全部五种选择的安装器目标。发行脚本原本复制**所有受版本控制的 configs 文件**，会把开发测试 `configs/config.yaml` 带入正式包；实现阶段已开始修复此输入边界，仍需重新发布发行资产才对用户生效。

VMM 已支持 `vmm-local service install|uninstall|start|stop|status|run`。Windows SCM、Linux systemd、macOS launchd 均已实现；安装服务当前自动启用，未提供独立的开机自启开关与 `restart`。服务运行路径只接受服务名，`run` 内固定使用默认配置根；作为系统服务时，账户主目录可能不同于执行安装器的用户。服务模式必须先获得明确的配置根传递与持久化契约，才能保证交互配置真正生效。

## 三、目标架构与技术选型

1. **独立 Go 单文件管理器**：命令名 `vmmm`。TUI 使用 Bubble Tea v2；展示层仅依赖应用服务接口，安装、下载、配置与服务操作可由非交互测试调用。首次实现锁定 [Bubble Tea v2.0.9](https://github.com/charmbracelet/bubbletea/releases/tag/v2.0.9)，模块最低 Go 版本为 1.25.0，并提交 `go.sum`；其 `View` 返回 `tea.View`，使用 `tea.KeyPressMsg`。管理器拥有自己的仓库、版本、五平台构建、Release、签名清单和更新周期；其发行包不包含 VMM 运行时。
2. **两个极薄引导脚本**：`install.ps1` 与 `install.sh` 只识别平台/架构、选择明确版本、从 GitHub 官方、预置 GitHub 代理或用户填写的 HTTPS GitHub 代理下载 VMMM 发行物，核对脚本内固定的官方完整 SHA-256 后执行 `vmmm install`。脚本不写 VMM 配置、不注册服务，也不下载 VMM 包。Windows 示例入口形态为 `irm <管理器脚本 HTTPS 地址> | iex`，POSIX 为 `curl -fsSL <管理器脚本 HTTPS 地址> | sh`；正式文档优先给出可审阅的先下载再执行方式，并说明管道入口若经过第三方代理，脚本自身不具备独立真实性保证。管理器尚无 Release，代理对管理器资产的支持须在发布后单独验收。
3. **权威配置桥**：在 VMM 增加版本化 `config schema --json` 与 `config validate -config <root> --json` 只读命令，模式描述包含字段路径、类型、默认值、枚举、条件生效、保密属性和弃用标志；校验直接调用现有 `ResolvePromptLayout`、`LoadPaths`、`Validate` 及规则资产校验。VMMM 通过子进程和稳定 JSON 协议使用，不跨仓库导入 `internal/config`，避免复制业务校验器。
4. **双层配置编辑**：向导处理常用安装、存储、供应商、网络和安全字段；高级编辑器保留 YAML 未认识节点、注释与顺序，允许查看最终合并来源、编辑所有 schema 字段及用户规则文件。写入前生成差异、备份并调用 VMM 校验；未知版本的未知字段只允许只读，禁止猜测写入。
5. **平台适配器与完整 VMM 包**：下载、安装事务与版本切换共用核心；Windows/Linux/macOS 各自处理 PATH、权限、服务、自启和终端路径。经用户确认，首版每个平台发行一份包含 native、split、controller 依赖的完整 VMM 包，并在包内能力清单明确列出实际支持的存储模式；PostgreSQL/ParadeDB 复用同一 Go 运行时并要求外部数据库。首期仅支持 VMM 发行矩阵的五个平台，不从源码临时编译。
6. **发布信任链**：经用户确认，PS1/sh 引导脚本内固定管理器版本、平台和从官方核实的完整 SHA-256，不要求目标机器预装 Ed25519 验证工具；脚本本身须从受信入口取得。VMMM 内部使用项目方受控公钥验证后续 VMMM 与 VMM 的 Ed25519 签名清单，再核对固定版本、平台、资产 SHA-256 和 VMM 包内逐文件摘要。远端 `latest` 解析完成后立即钉住 tag、源提交和资源摘要。第三方代理必须提供与官方字节一致的资产，不能降级为只校验代理自己发布的摘要。私钥保管、轮换及吊销仍需发布流程落实。

7. **显式下载源**：管理器首次启动展示 GitHub 官方源、`ghproxy.net`、`gh-proxy.org`、`ghfast.top` 三个第三方 GitHub 代理，以及自定义 HTTPS GitHub 代理前缀。用户已明确本轮“镜像”指 GitHub 下载代理，暂不实现自建静态文件镜像。三个代理的预置资格来自本次真实 VMM 发行资产探测，不能代替安装时检测。选择 VMM 下载源发生在下载 VMM 包之前，后续升级沿用已保存选择，可随时修改。管理器引导源与 VMM 下载源相互独立；下载失败时由用户选择重试或切源，不静默切换。候选证据、检测步骤和自定义 URL 契约见[下载源调研](../DOWNLOAD_SOURCES_CN.md)。

建议目录：`cmd/vmmm`、`internal/domain`、`internal/configbridge`、`internal/release`、`internal/install`、`internal/service`、`internal/platform`、`internal/tui`、`internal/i18n`、`scripts/install.ps1`、`scripts/install.sh`、`docs/`。代码按仓库约定使用英文第一行、中文第二行注释；每个源码文件有职责、所在层和调用链文件头。

## 四、交互、命令与状态

首次进入：语言选择（默认终端语言，首发简体中文与英语，可即时切换）→ 检测已有安装与服务 → 选择 VMM 下载源（GitHub 官方、三个预置第三方代理或自定义 HTTPS GitHub 代理）并显示实时检测结果 → 发行版本/安装目录 → 下载及校验 → 存储模式和数据路径 → LLM/embedding/rerank 快捷配置 → 网络/日志/规则高级配置 → 选择前台命令行或系统服务、是否开机自启、是否加入 PATH → 汇总差异及配置检查 → 执行安装 → 启动及健康检查 → 生成安装报告。

已安装首页：管理器版本、VMM 版本与下载源、配置根、数据根、运行状态、服务状态、开机自启、PATH、最近校验时间；操作包括启动、停止、重启、前台运行、注册/注销服务、切换自启、更改下载源、编辑配置、检查配置、诊断、升级、回滚、卸载程序。卸载时分别确认程序、服务、配置和数据库，默认保留配置与数据。无法判定文件归属时只报告，不删除。

非交互命令至少包括 `vmmm install`、`open`、`status`、`start`、`stop`、`restart`、`service install|uninstall|enable|disable|status`、`config edit|validate|show-effective`、`upgrade`、`rollback`、`uninstall`、`doctor`、`version`。无参数且有 TTY 时打开 TUI；无 TTY 返回帮助与非零码。`vmmm` 是管理器，`vmm-local` 仍是业务运行时，避免同名覆盖。

供应商快捷配置提供独立的 LLM、embedding、rerank 步骤及 OpenAI 兼容通道；展示真实 provider ID、endpoint、model、维度、key 池和限额。凭据默认写入权限收紧的服务可读 `.env`，YAML 使用 `${NAME}` 引用；多 API Key 采用稳定变量名。验证分层显示：静态结构、凭据是否存在、端点可达、可选实际推理/embedding 测试。实际请求可能收费，必须由用户明确触发并展示结果，不能把网络失败解释成 YAML 无效。

## 五、安装事务和路径契约

安装登记文件记录 manager 版本、VMM tag/commit/平台、程序根、配置根、数据根、服务名/账户、自启状态、PATH 所有权、文件清单及校验摘要，不记录明文密钥。运行时安装根保持稳定的 `bin/`、`configs/`、`libs/` 相对布局；下载到同卷隔离暂存区，检查 archive 遍历、符号链接越界、重复条目、平台与摘要后再切换。升级先停服务、备份程序和配置、替换受管理程序文件、调用新版本校验与健康检查，失败回退旧程序和旧配置；不自动回滚已经迁移的数据。暂存与回滚不触碰用户数据目录。

服务模式选机器级配置根并保存为服务注册参数；命令行模式可选用户 `~/.vmm`。必须在 VMM 中扩展 service CLI，使 `install/run` 保留且显式传入配置根，以及分别控制服务安装、启动、自启；或者采用版本化环境文件且由 VMM 服务入口读取。本文首选**显式 `-config` 根参数**，路径在注册时固定、展示、校验、卸载时核对归属。Windows、Linux、macOS 均不得依赖交互用户 `HOME`。服务需要数据和配置的最小权限，安装目录对服务账户只读，数据与日志目录可写；提权只覆盖必要服务操作。若现有模式数据绑定在旧程序根，升级前应保持该数据路径稳定或走受支持迁移，禁止通过移动目录暗中换库。

PATH 只加入管理器安装目录。Windows 更新目标范围的 PATH 注册表项并广播环境变化；POSIX 首选用户明确选择的 profile 片段或已存在的标准用户 bin 链接。保存安装器写入的原始值/链接所有权，卸载只撤销本管理器写入的部分，不改写同名第三方命令。已存在不同来源的 `vmmm` 必须提示冲突。

## 六、配置校验和错误分级

1. **静态校验**：发行物身份、目录布局、配置层路径、YAML 解码、未知字段、类型/枚举、跨字段约束、环境变量引用、规则资产和提示词包；以 VMM `config validate` 为权威，VMMM 只做输入即时提示。
2. **运行条件校验**：动态库 ABI/能力、数据库文件权限与路径不重叠、端口占用、PostgreSQL 连接与扩展、controller 可达性、服务账户可读凭据。只读探测与可能改动数据库的启动初始化要分开标示。
3. **实际健康检查**：启动后观察服务管理器状态和 gRPC/管理端点就绪；可选供应商调用单列，不混进安装通过条件。

错误结果包含阶段、字段路径、配置来源层、原因、是否可重试、建议动作和敏感信息脱敏。校验失败禁止启动/切换服务；不能以多路径回退隐藏真实配置错误。

## 七、实施阶段、验证与完成标准

| 阶段 | 工作 | 必须通过的验收 |
| --- | --- | --- |
| 0. 上游契约 | 修正 VMM 发行包 `configs/config.yaml`；改为五平台完整 `all` 包并记录真实能力；增加机器可读 schema/validate；补服务显式配置根、自启控制；版本化 JSON 协议 | 五平台发行包无本地测试密钥依赖且具备 native、split、controller 依赖；服务与前台在同一配置根读取相同有效配置；VMM 原有测试及打包测试通过。 |
| 1. 管理器核心 | 初始化 Go 模块、安装登记、独立发行格式、GitHub 官方与三个内置代理的双产品源解析、自定义 HTTPS 代理的输入和探测、下载验证、平台检测、暂存/回滚、非交互命令 | 管理器发行物不含 VMM；预置和自定义代理均须实时探测并显示失败阶段；假包、错平台、错摘要、路径穿越、断网、断电恢复、重复安装均有确定结果；不损坏旧安装。 |
| 2. 配置编辑 | schema 驱动表单、无损高级 YAML、供应商向导、规则资产、凭据和三层校验 | 所有 VMM schema 字段可查看和修改；未知节点不被丢弃；保存前与 VMM 真实校验结果一致；密钥不入日志。 |
| 3. TUI 与本地化 | 首装、已安装首页、进度、错误恢复、中文/英文消息目录 | 80×24 终端、终端宽度变化、无色终端、中文输入、取消与返回路径可用；无 TTY 行为清楚。 |
| 4. 服务与 PATH | 三平台服务/自启适配、运行状态、提权、PATH 所有权 | 安装、启动、停止、重启、注销、启停自启及卸载保留数据都通过各目标平台原生运行验收。 |
| 5. 发布与文档 | 管理器独立五平台发行、可信签名、引导脚本、固定版本安装、官方与三个第三方代理的管理器资产验收、自定义 GitHub 代理验证、升级/回滚指南 | 引导脚本只下载管理器；两仓库版本可独立演进；同一 VMM 资产在官方与所选代理的完整摘要一致；从干净机器到运行中 VMM 的完整路径可复现。 |

修改 VMM 请求校验、服务或配置加载路径后执行仓库规定的聚焦 `go test` 与 `go test ./...`；触及打包路径执行 `make.ps1 build` 或 `make.bat build`，并在 Linux/macOS 原生环境分别验收。管理器至少做纯逻辑单测、假服务/假下载故障注入、五平台安装集成、实际服务生命周期和真实发行包端到端验收。跨编译仅证明构建，不代替平台原生运行测试。

完成定义：用户可从引导脚本进入 TUI，选择五种清楚标注的存储方案之一，配置真实可用供应商和全部配置项，获得 VMM 权威校验；前台及服务模式都能按保存的配置启动；`vmmm` 能恢复进入管理界面，完成服务、升级、回滚与保留数据的卸载。任一阶段的失败不得留下“显示成功但配置未生效”的安装。

审核退出条件：实现与必要的测试完成后，按照用户最新指示由当前智能体独立逐轮检查实际变更、关键调用链、平台行为与测试证据，不使用子代理。每轮记录范围、发现和修复；一旦发现任何需要修复的问题，立即修复并将连续无问题轮数归零。只有连续五轮均未发现问题，且最终构建与测试仍通过，才结束目标。审核结论必须按真实覆盖范围表述，不能把交叉编译当成其他系统的原生运行验收。

## 八、需在实施前确认的重大决策

1. VMM 增加 `config schema/validate` 和显式服务配置根，属于运行时 CLI 协议调整；建议按本方案实施，并在 VMM 仓库单独评审与提交。
2. 用户已确认首版安全协议：引导脚本固定版本与官方 SHA-256，管理器内部使用 Ed25519 校验后续更新清单。用户随后授权立即生成 VMMM 与 VMM 两套独立 Ed25519 发行密钥；私钥种子只通过标准输入写入各自仓库的 GitHub Actions Secrets，公钥提交至仓库作为固定信任根。Certum Windows 程序代码签名证书仍在办理，须预留接入，不能把 Ed25519 清单签名误当成 Windows 代码签名；未达到正式发行签名要求前不开放 `curl|sh` / `irm|iex` 正式入口。发布前还需验证密钥轮换与吊销流程、引导脚本自身的受信分发入口；自定义代理不得因可访问就被标为等价官方来源。
3. 系统服务采用机器级配置与独立数据根；需要确定首发是否允许用户级服务，以及各平台服务账户和默认安装路径。
4. 数据库模式切换与 embedding 身份变化均走显式迁移流程；首发是否实现跨模式迁移，或只允许新安装选择模式并对既有实例阻止切换。
5. 用户已确认每个平台采用完整 `all` 发行包，覆盖 native、split、controller 外部依赖；PostgreSQL 与 ParadeDB 使用同一运行时并连接外部数据库。已发布的 `v0.1.0` 不能回溯视为完整包，管理器安装最低可用版本须以新发行资产的能力清单为准。

## 九、前期方案阶段变更总结

以下记录的是实施启动前的方案设计，不代表当前目标已完成。

1. 核心修复与调整概述：依据 VMM 当前源码澄清配置层、五种面向用户的存储选择、检索算法、发行和服务边界，制定独立管理器方案；补充管理器独立发行、双阶段源选择、三个预置第三方 GitHub 代理的真实资产探测与自定义代理校验契约。
2. 📂文件变更清单：新增本方案文档、仓库入口说明及下载源调研。VMM 源码无修改、无删除。
3. 💻关键代码调整详情：本次无代码调整。后续拟新增 VMM 配置契约命令及服务配置根传参，并在管理器实现事务式安装和配置桥。
4. ⚠️遗留问题与注意事项：VMM 发行配置和服务配置根是实施前置阻塞；签名协议、服务账户及跨模式迁移范围待用户确认；尚无已核实的 OpenVulcan 正式国内镜像 HTTPS 基址。计划保持在 `docs/plan/`，待真正完成实现和全平台验收后再迁入 `docs/completed/20260923/`。

## 九点一、实施期新增确认

2026 年 9 月 23 日，用户确认 VMM 的 split 与 controller 模式可以新增显式本地数据根目录配置字段，并要求旧配置继续沿用原有路径。实施时必须覆盖运行时、维护工具和迁移工具的真实调用链；切换已有数据库路径不得静默创建空库或误报迁移完成。安装器只在所选 VMM 版本的权威配置清单包含该字段时开放编辑。

同日用户确认安装器 TUI 采用 Bubble Tea v2.0.9。管理器仓库使用 Go 1.25.0，并锁定对应模块依赖与校验和。

## 十、源码依据

- `VulcanMemoryMesh/internal/config/config.go`：顶层及嵌套配置类型。
- `VulcanMemoryMesh/internal/config/loader.go`、`config_load.go`、`config_validate.go`：配置发现、合并、环境变量、严格解码与校验。
- `VulcanMemoryMesh/configs/base.yaml`、`configs/config.yaml`：系统底座与当前随包覆盖。
- `VulcanMemoryMesh/internal/app/native_storage_layout.go`、`local_storage_layout.go`、`internal/app/usecase/memory_query_search.go`：路径与检索流程。
- `VulcanMemoryMesh/internal/adapters/outbound/vldb_postgres/dialect_standard.go`、`dialect_paradedb.go`：PostgreSQL 两种词法方言。
- `VulcanMemoryMesh/cmd/vmm-local/main.go`、`service_*.go`：运行与服务命令。
- `VulcanMemoryMesh/scripts/release.py`、`docs/github-release-guide_CN.md`：正式包结构与发行资产。

## 十一、实施审核记录（2026 年 9 月 23 日）

审核过程中曾发现方案仍将自建静态文件镜像列为首版验收项，与用户后来明确的 GitHub 下载代理范围不一致；已修正下载源调研与本计划，并将连续无问题轮数归零。修正后由当前智能体独立完成以下五轮，均未发现新的待修复问题：

| 连续轮次 | 审核范围 | 核验证据 | 结论 |
| --- | --- | --- | --- |
| 1 | 下载源、HTTPS 重定向、固定摘要、Ed25519 清单、独立发行流程 | 管理器相关 7 包 98 项 Go 测试、引导与签名脚本 15 项测试、差异空白检查 | 无新问题 |
| 2 | 安装暂存、提交、回滚、卸载、状态所有权与 VMM 运行配置 | 管理器 4 包 61 项、VMM 3 包 273 项 Go 测试；逐项检查安装事务和受控删除路径 | 无新问题 |
| 3 | YAML 节点编辑、schema、敏感字段、供应商凭据和校验桥 | 管理器 6 包 64 项、VMM 3 包 246 项 Go 测试；核对敏感 JSON 字段及权威校验路径 | 无新问题 |
| 4 | 三平台服务命令、Unix 服务账户、PATH 登记与撤销、后台进程身份 | 管理器 4 包 53 项、VMM 服务入口 32 项 Go 测试；核对提权和服务状态协议 | 无新问题 |
| 5 | TUI 首装与已安装页面、双语资源、引导脚本、发行门禁及全量回归 | 管理器 299 项和 VMM 1287 项 Go 测试、两仓库 `go vet`、管理器 20 项及 VMM 19 项脚本测试（VMM 1 项因本机无 shell 跳过），三平台 PR CI 各 6 项通过 | 无新问题 |

本记录只说明当时已审核代码与自动化验证范围。Certum Windows 代码签名证书尚未到位，管理器目前只有草稿发行工作流，尚无公开 Release；引导脚本模板因此保持失败关闭。后续已增加 VMM 五平台真实服务管理器验收，但管理器通过公开发行包完成干净机器整包下载、特权安装和实际供应商调用仍待正式发行验收。计划保持“实施中”，在上述发布与原生端到端验收完成前不迁入 `docs/completed/`。

## 十二、最终审核重新计数

此前表格中的五轮结果针对当时的代码与测试范围。后续五平台真实服务测试发现 Linux 原生库调用与 macOS 服务属性列表问题，已在 VMM 修复；继续审核管理器时又发现首次安装服务账户的预检错误要求其拥有管理员父目录的写权限，现已修复并补充 Unix 回归测试。因此此前五轮不作为最终退出依据，连续无问题轮数重新归零。后续须以两个仓库的最终提交、五平台完整包和独立账户服务验收结果重新完成连续五轮审核。
