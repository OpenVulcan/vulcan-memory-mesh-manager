# VMMM 与 VMM 独立发行及 GitHub 下载代理调研

调研日期：2026-09-23。这里的“国内镜像”特指面向国内用户的 GitHub Release 下载代理，不要求 OpenVulcan 自建对象存储。候选连通性来自当前 Windows 主机的一次探测；未在不同省份、运营商或整包下载场景测量速度和长期稳定性。

## 一、当前公开状态

| 对象 | 已核实状态 | 依据 |
| --- | --- | --- |
| VMM 官方发行 | GitHub `OpenVulcan/vulcan-memory-mesh` 已发布 `v0.1.0`，含五个平台的压缩包、逐平台 JSON 和 `SHA256SUMS`。 | [VMM GitHub Releases](https://github.com/OpenVulcan/vulcan-memory-mesh/releases) |
| VMMM 管理器发行 | `OpenVulcan/vulcan-memory-mesh-manager` 目前没有公开 Release。 | [VMMM GitHub Releases](https://github.com/OpenVulcan/vulcan-memory-mesh-manager/releases) |
| OpenVulcan 自有国内 HTTPS 镜像 | 在上述发行页、当前 VMM 源码和公开搜索中，**未核实到项目方公布的固定国内下载基址**。这不等于断言项目方没有私有镜像；第三方 GitHub 代理仍可提供默认下载选项。 | [VMM GitHub Releases](https://github.com/OpenVulcan/vulcan-memory-mesh/releases)、VMM 本地 `README.md` 与 `scripts/release.py` |

首版源列表应预置 GitHub 官方源和下表通过本次探测的 GitHub 代理，同时支持用户输入自己的代理前缀。界面必须把代理标为“第三方”，不能将它们写成 OpenVulcan 官方地址。可用性由安装时的实时检测决定，不能靠本次探测结果永久判定。

## 二、默认 GitHub 代理候选及本次探测

测试对象为 VMM `v0.1.0` 官方 `SHA256SUMS`。从[官方 Release](https://github.com/OpenVulcan/vulcan-memory-mesh/releases)可核对该文件 SHA-256 为 `ca8101f845b10dfd0e60d02b6f88abc89143e12ea20cc1968873bd8822bc6763`；当前主机直接下载得到 1093 字节。每个候选还请求 Windows x64 ZIP 的前 1024 字节，检查是否返回 ZIP 头 `504b0304`、是否遵守 HTTP Range。这里没有下载和校验完整的 123238027 字节压缩包。

| 预置候选 | 维护/站点依据 | 校验文件 | 大文件前 1 KiB | 默认支持结论 |
| --- | --- | --- | --- |
| `https://ghproxy.net/` | [站点](https://ghproxy.net/)指向公开的 [hunshcn/gh-proxy](https://github.com/hunshcn/gh-proxy) 项目。 | HTTP 200；1093 字节；SHA-256 与官方一致。 | HTTP 206；ZIP 头正确；支持 Range。 | 预置，标记第三方；安装时重新检测。 |
| `https://gh-proxy.org/` | [服务文档](https://gh-proxy.com/docs/github-accelerator)给出 GitHub Release 代理用法；首页跳转到 `gh-proxy.com`。 | HTTP 200；1093 字节；SHA-256 与官方一致。 | HTTP 206；ZIP 头正确；支持 Range。 | 预置，标记第三方；安装时重新检测。 |
| `https://ghfast.top/` | [站点](https://ghfast.top/)提供 GitHub 代理界面；公开运营信息比前两者少。 | HTTP 200；1093 字节；SHA-256 与官方一致。 | HTTP 206；ZIP 头正确；支持 Range。 | 预置为第三个备选，安装时重新检测并显示来源信息不足。 |

其他探测结果：`gh.2i.gs` 的文件摘要一致，但[站点自称仅供演示](https://gh.2i.gs/)，并对 Range 请求返回 HTTP 200，故不预置；`ghproxy.vip` 摘要与片段通过，但站点首页本次读取超时，暂不预置；`ghproxy.1888866.xyz` 本次超时；`ghproxy.cn` 返回了 6990 字节的不同内容；`mirror.ghproxy.com` 未解析成功。这些失败只表示当前主机、当前时刻的结果。

“名声好”无法仅凭站点名称证明。本次预置依据是公开说明、可识别的服务入口和**针对 VMM 实际发行资产**的内容探测；任何代理都不能因此获得官方信任等级。项目方未来也可另外部署[腾讯 COS](https://cloud.tencent.com/document/product/436/18670)或[阿里 OSS](https://help.aliyun.com/zh/oss/user-guide/access-oss-by-https-protocol)等自有静态镜像，但这不是本轮默认代理方案的前置条件。

## 三、两个产品各自发行

`vmmm` 与 `vmm-local` 独立版本、独立仓库、独立 CI 和独立发行资产。VMMM 的 Release 只含管理器单文件程序、引导脚本、VMMM 版本化清单与签名；**不打进 VMM 服务端压缩包**。VMM 继续在自己的 Release 中发布五平台压缩包及其清单。管理器可以先升级自身，随后由用户选择是否升级 VMM；管理器版本号不与 VMM 版本号绑死。

管理器拟采用与 VMM 对齐的五平台矩阵：Windows x64、Linux x64/ARM64、macOS Intel/ARM64。发行资产名称、平台键和发布通道由 VMMM 自己的构建流程统一生成，不能从 VMM 的 `VERSION` 推断。每个平台都要在相应原生运行环境验证 TUI、终端输入及下载。

建议管理器直接发布单一可执行资产，例如 `vmmm-v0.1.0-windows-x64.exe`、`vmmm-v0.1.0-linux-x64`、`vmmm-v0.1.0-macos-arm64`；脚本只取当前平台的一个程序文件、VMMM 清单及签名，不必先解压 VMM 压缩包。语言资源编入管理器。VMM 原有 `vulcan-memory-mesh-<版本>-<平台>.zip/tar.gz` 保持由 VMM 自己发布、由运行中的管理器下载。

引导脚本的工作仅是下载 VMMM、核对脚本内固定的官方完整 SHA-256，再执行 VMMM。VMMM TUI 负责选择 VMM 下载源、下载 VMM、配置和实际安装。即使两个产品都在 GitHub，脚本仍只能访问管理器仓库的发行资产；不得把 VMM 压缩包混入管理器发行物。若脚本本身经第三方代理取得，代理仍可能篡改脚本，故正式入口须优先使用受信官方 HTTPS 并给出脚本审阅/独立校验方式。

## 四、下载源选择与自定义契约

在引导脚本阶段支持 `GitHub 官方`、三条内置 GitHub 代理和 `自定义 GitHub 代理前缀`，通过参数或环境变量选择；`sh` 从管道执行时不得依赖被脚本占用的标准输入，应读取明确参数或 `/dev/tty`。由于 VMMM 尚未发布 Release，本次只能用 VMM 资产验证代理，管理器资产要在它首次发布后另行验收。

管理器下载成功后，TUI 再独立展示 VMM 源：`GitHub 官方`、`ghproxy.net`、`gh-proxy.org`、`ghfast.top`、`自定义 GitHub 代理前缀`；另设 `自定义静态 HTTPS 镜像` 供用户自建镜像。引导源和 VMM 源可不同；用户选择的 VMM 源用于后续升级，并在首页可查看与修改。选择源是显式操作，下载失败时给出重试或切换选择，不静默改用另一来源。

默认和自定义 GitHub 代理统一使用此构造：`<代理 HTTPS 前缀>https://github.com/OpenVulcan/<仓库>/releases/download/<tag>/<固定资产文件名>`。仓库只允许 `vulcan-memory-mesh-manager` 或 `vulcan-memory-mesh`，tag 与文件名来自可信版本清单。代理前缀在目录中有稳定 ID，不使用“输入一个 URL，尝试多种拼法”的模糊回退。

自定义静态镜像输入为一个 HTTPS 根 URL，例如 `https://downloads.example.org/openvulcan/`，该域名仅是格式示例。用户输入时校验协议、主机、端口、路径、证书、重定向结果及清单结构；拒绝 URL 中的账号密码、查询串和片段。允许用户自建内网 HTTPS 镜像；最终下载 URL 从清单中的**固定文件名**和受控目录拼接，禁止 `..`、绝对路径、跨主机资产 URL 与路径穿越。

自定义 GitHub 代理输入为 HTTPS 前缀，例如 `https://proxy.example.org/`；管理器仅将已知的 GitHub 官方资产 URL 作为代理参数，不让用户提交任意上游 URL。输入时拒绝非 HTTPS、账号密码、查询串、片段及明显无效路径；允许用户显式配置带端口或子路径的自建代理。用户可在 TUI 中执行“检测并保存”；检测失败时保留输入供修正，但不能将该源用于安装。

源检测分三步显示结果：① TLS 和域名连接；② 通过该代理获取一个已知 VMM 版本的 `SHA256SUMS`，要求 HTTP 200、预期大小且摘要与**可信官方值**一致，不能只信代理返回的校验文件；③ 对同版本实际压缩包发送 `Range: bytes=0-1023`，验证 ZIP/tar.gz 文件头、总大小和 HTTP 206。HTTP 200 但文件头正确时可标为“可下载，未证实续传”，不计为范围请求通过。安装时还必须流式下载**整个**资产并核对可信 SHA-256、包内清单和运行版本；本次探测不能代替整包验收。源状态显示检测时间和具体失败阶段，打开 TUI 与每次升级前重新检测。

建议静态镜像目录采用独立产品命名空间：

```text
<基址>/vmmm/channels/stable.json
<基址>/vmmm/releases/<管理器版本>/manifest.json
<基址>/vmmm/releases/<管理器版本>/<管理器平台资产>
<基址>/vmm/channels/stable.json
<基址>/vmm/releases/<VMM版本>/manifest.json
<基址>/vmm/releases/<VMM版本>/<VMM平台资产>
```

`stable.json` 只负责解析到确定版本及签名清单；版本清单记录产品 ID、tag、源提交、平台、文件名、字节数、SHA-256、签名 key ID 与协议版本。下载前固定产品、版本与平台，下载后核对字节数、摘要、VMM 包内逐文件清单和可执行文件 `-version-json`。镜像必须与 GitHub 官方**字节一致**；同步器先核对官方发行物，全部上传且公开探测通过后，再发布通道指针。旧版本保留，避免更新过程中读到半套资产。

当前 VMM `v0.1.0` 的 `SHA256SUMS` 与逐平台 JSON 随同包发布，但它们本身不能证明代理提供的同名文件来自 OpenVulcan。经用户确认，首版引导脚本固定管理器版本与从官方核实的资产 SHA-256，管理器内部使用 Ed25519 验证后续版本清单；PS1/sh 不依赖目标机器预装 OpenSSL。后续应在 VMM 与 VMMM 各自发行流程增加项目方签名的版本清单，并把可信公钥内置于管理器。GitHub 官方源可通过 [GitHub Release API 的 asset `digest`](https://docs.github.com/en/rest/releases/assets) 再核对；在完全无法访问 GitHub 时，只有本地已信任或签名验证通过的版本摘要才允许安装。管理器还应记录已安装版本并拒绝代理提供更旧的“最新版本”，除非用户显式选择降级。

## 五、实施建议和验收

1. 先在 VMMM 仓库建立独立构建/发行流程、资产格式和脚本单独下载路径；不修改 VMM 发布脚本来塞入管理器。
2. 将 GitHub 官方及三个默认代理作为版本化内置源目录；TUI 支持逐个检测、选择、保存、重新选择和输入自定义前缀。引导脚本也接受默认代理 ID 或自定义管理器下载源。
3. VMMM 首次发布 Release 后，逐一用**管理器**的真实小型清单与单文件资产验证三个代理；未通过者暂不在引导脚本中启用，不能从 VMM 的通过结果推断管理器必然可用。
4. 每次安装从选定源完整下载，核对可信文件摘要、大小、版本与包内清单；覆盖错误页面、证书失败、HTTP 200 伪成功、Range 不支持、半途断开、代理返回旧版本以及用户切源。
5. 在中国内地网络分别测量实际连通性、完整下载速度和失败率后，再决定默认提示排序；本次仅从当前主机做小文件和首 1 KiB 探测，不做速度承诺。

结论：预置 GitHub 官方、`ghproxy.net`、`gh-proxy.org`、`ghfast.top` 四个选项；后三者明确标为第三方 GitHub 代理，均须安装时动态检测。用户还可输入自己的 HTTPS GitHub 代理前缀并检测。没有已核实的 OpenVulcan 自有国内基址，也没有对三个代理做整包或中国内地多网络验收。
