# This script downloads one VMMM manager release fixed by an injected official SHA-256.
# 此脚本只下载由注入的官方 SHA-256 固定的 VMMM 管理器发行物。

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Source = '',

    [string] $ProxyPrefix = '',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ManagerArguments = @()
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# The release generator replaces every marker before a script can be published.
# 发布生成器会在脚本发布前替换所有标记；模板状态必须保持失败关闭。
$script:VMMMRepository = 'OpenVulcan/vulcan-memory-mesh-manager'
$script:VMMMVersion = '__VMMM_VERSION__'
$script:VMMMAssetNames = @{
    'windows-x64' = '__VMMM_ASSET_WINDOWS_X64__'
    'linux-x64' = '__VMMM_ASSET_LINUX_X64__'
    'linux-arm64' = '__VMMM_ASSET_LINUX_ARM64__'
    'macos-intel' = '__VMMM_ASSET_MACOS_INTEL__'
    'macos-arm64' = '__VMMM_ASSET_MACOS_ARM64__'
}
$script:VMMMSHA256 = @{
    'windows-x64' = '__VMMM_SHA256_WINDOWS_X64__'
    'linux-x64' = '__VMMM_SHA256_LINUX_X64__'
    'linux-arm64' = '__VMMM_SHA256_LINUX_ARM64__'
    'macos-intel' = '__VMMM_SHA256_MACOS_INTEL__'
    'macos-arm64' = '__VMMM_SHA256_MACOS_ARM64__'
}
# MaxManagerBytes bounds untrusted proxy responses before their release digest is checked.
# MaxManagerBytes 在发行摘要校验前限制不可信代理响应大小。
$script:MaxManagerBytes = [long]536870912

function Stop-Bootstrap {
    <#
    Stop the bootstrap with a concise bilingual diagnostic.
    使用简洁的双语诊断终止引导脚本。
    #>
    param([Parameter(Mandatory = $true)][string] $Message)
    throw "vmmm bootstrap: $Message"
}

function Test-SafeVersion {
    <#
    Validate an injected release tag without accepting URL path syntax.
    校验注入的发行标签，拒绝 URL 路径语法。
    #>
    param([Parameter(Mandatory = $true)][string] $Value)
    return $Value -match '^v[0-9A-Za-z][0-9A-Za-z._-]*$'
}

function Test-SafeAssetName {
    <#
    Validate a generated asset filename as one path component.
    校验生成的资产文件名只能是单个路径组件。
    #>
    param([Parameter(Mandatory = $true)][string] $Value)
    return $Value -ne '.' -and $Value -ne '..' -and $Value -match '^[A-Za-z0-9._-]+$'
}

function Test-SHA256 {
    <#
    Validate the exact 64-hex digest embedded by the release process.
    校验发布流程注入的精确 64 位十六进制摘要。
    #>
    param([Parameter(Mandatory = $true)][string] $Value)
    return $Value -match '^[0-9a-fA-F]{64}$'
}

function Assert-InjectedRelease {
    <#
    Refuse to download when the source template was not release-rendered.
    如果源模板未经过发布渲染，则拒绝下载。
    #>
    if (-not (Test-SafeVersion $script:VMMMVersion)) {
        Stop-Bootstrap 'the bootstrap template has no valid injected release version / 引导脚本没有有效的注入版本'
    }
    foreach ($platformId in @('windows-x64', 'linux-x64', 'linux-arm64', 'macos-intel', 'macos-arm64')) {
        if (-not (Test-SafeAssetName $script:VMMMAssetNames[$platformId])) {
            Stop-Bootstrap "$platformId asset metadata is not injected / 未注入 $platformId 资产信息"
        }
        if (-not (Test-SHA256 $script:VMMMSHA256[$platformId])) {
            Stop-Bootstrap "$platformId SHA-256 is not injected / 未注入 $platformId SHA-256"
        }
    }
}

function Assert-HttpsProxyPrefix {
    <#
    Validate a custom HTTPS proxy prefix before fixed URL concatenation.
    在拼接固定 URL 前校验自定义 HTTPS 代理前缀。
    #>
    param([Parameter(Mandatory = $true)][string] $Prefix)
    if ($Prefix -notmatch '^https://') {
        Stop-Bootstrap 'custom proxy prefix must start with https:// / 自定义代理前缀必须以 https:// 开头'
    }
    if (-not $Prefix.EndsWith('/')) {
        Stop-Bootstrap 'custom proxy prefix must end with / / 自定义代理前缀必须以 / 结尾'
    }
    if ($Prefix -match '[\s\r\n@?#\\]') {
        Stop-Bootstrap 'custom proxy prefix contains a forbidden URL character / 自定义代理前缀包含禁止的 URL 字符'
    }
    try {
        $uri = New-Object System.Uri -ArgumentList $Prefix
    } catch {
        Stop-Bootstrap 'custom proxy prefix is not a valid URI / 自定义代理前缀不是有效 URI'
    }
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($uri.Host) -or $uri.UserInfo) {
        Stop-Bootstrap 'custom proxy prefix must be an HTTPS URI without credentials / 自定义代理前缀必须是无凭据的 HTTPS URI'
    }
    if ($uri.Query -or $uri.Fragment) {
        Stop-Bootstrap 'custom proxy prefix cannot contain query or fragment / 自定义代理前缀不能包含查询串或片段'
    }
}

function Get-SourcePrefix {
    <#
    Resolve one explicit source ID to its trusted prefix contract.
    将明确的源 ID 解析为受支持的前缀契约。
    #>
    param(
        [Parameter(Mandatory = $true)][string] $SelectedSource,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $SelectedPrefix
    )
    switch -CaseSensitive ($SelectedSource) {
        'official' {
            if ($SelectedPrefix) { Stop-Bootstrap 'official source cannot use a proxy prefix / 官方源不能同时使用代理前缀' }
            return ''
        }
        'ghproxy-net' {
            if ($SelectedPrefix) { Stop-Bootstrap 'built-in source cannot use a custom prefix / 内置源不能同时使用自定义前缀' }
            return 'https://ghproxy.net/'
        }
        'gh-proxy-org' {
            if ($SelectedPrefix) { Stop-Bootstrap 'built-in source cannot use a custom prefix / 内置源不能同时使用自定义前缀' }
            return 'https://gh-proxy.org/'
        }
        'ghfast-top' {
            if ($SelectedPrefix) { Stop-Bootstrap 'built-in source cannot use a custom prefix / 内置源不能同时使用自定义前缀' }
            return 'https://ghfast.top/'
        }
        'custom' {
            if (-not $SelectedPrefix) { Stop-Bootstrap 'custom source requires -ProxyPrefix or VMMM_BOOTSTRAP_PROXY_PREFIX / 自定义源需要 -ProxyPrefix 或环境变量' }
            Assert-HttpsProxyPrefix $SelectedPrefix
            return $SelectedPrefix
        }
        default { Stop-Bootstrap "unsupported source: $SelectedSource / 不支持的下载源：$SelectedSource" }
    }
}

function Get-PlatformId {
    <#
    Return the only Windows platform identity supported by the release matrix.
    返回发行矩阵支持的 Windows 平台身份。
    #>
    if (-not [Environment]::Is64BitOperatingSystem) {
        Stop-Bootstrap 'only Windows x64 is supported / 仅支持 Windows x64'
    }
    return 'windows-x64'
}

function Download-SecureFile {
    <#
    Download over HTTPS with manual HTTPS-only redirect handling.
    使用手动的仅 HTTPS 重定向处理通过 HTTPS 下载文件。
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Url,
        [Parameter(Mandatory = $true)][string] $Destination
    )
    $client = $null
    $downloadTimeout = $null
    try {
        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient -ArgumentList $handler
        $client.Timeout = [TimeSpan]::FromMinutes(10)
        # ResponseHeadersRead stops the HttpClient timeout at headers, so one token covers redirects and body reads.
        # ResponseHeadersRead 使 HttpClient 超时在响应头结束，故用同一个令牌覆盖重定向与正文读取。
        $downloadTimeout = [System.Threading.CancellationTokenSource]::new()
        $downloadTimeout.CancelAfter([TimeSpan]::FromMinutes(10))
        $current = New-Object System.Uri -ArgumentList $Url
        for ($redirect = 0; $redirect -lt 5; $redirect++) {
            if ($current.Scheme -ne 'https') {
                Stop-Bootstrap 'download redirect was not HTTPS / 下载重定向不是 HTTPS'
            }
            $response = $client.GetAsync($current, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $downloadTimeout.Token).GetAwaiter().GetResult()
            try {
                $statusCode = [int]$response.StatusCode
                if ($statusCode -ge 300 -and $statusCode -lt 400) {
                    $location = $response.Headers.Location
                    if ($null -eq $location) {
                        Stop-Bootstrap 'download redirect has no location / 下载重定向缺少地址'
                    }
                    if (-not $location.IsAbsoluteUri) {
                        $location = New-Object System.Uri -ArgumentList $current, $location
                    }
                    $current = $location
                    continue
                }
                if ($statusCode -lt 200 -or $statusCode -ge 300) {
                    Stop-Bootstrap "manager download returned HTTP $statusCode / 管理器下载返回 HTTP $statusCode"
                }
                $contentLength = $response.Content.Headers.ContentLength
                if ($null -ne $contentLength -and $contentLength -gt $script:MaxManagerBytes) {
                    Stop-Bootstrap 'manager download exceeds the size limit / 管理器下载超过大小上限'
                }
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                try {
                    $outputStream = New-Object System.IO.FileStream -ArgumentList @(
                        $Destination,
                        [System.IO.FileMode]::CreateNew,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::None
                    )
                    try {
                        # Count actual streamed bytes because a proxy may omit or misstate Content-Length.
                        # 逐块统计实际字节，防止代理省略或伪造 Content-Length。
                        $buffer = [byte[]]::new(65536)
                        $received = [long]0
                        while (($count = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $downloadTimeout.Token).GetAwaiter().GetResult()) -gt 0) {
                            if ($count -gt ($script:MaxManagerBytes - $received)) {
                                Stop-Bootstrap 'manager download exceeds the size limit / 管理器下载超过大小上限'
                            }
                            $outputStream.Write($buffer, 0, $count)
                            $received += $count
                        }
                    } finally { $outputStream.Dispose() }
                } finally { $inputStream.Dispose() }
                return
            } finally { $response.Dispose() }
        }
        Stop-Bootstrap 'too many HTTPS redirects / HTTPS 重定向次数过多'
    } finally {
        if ($null -ne $downloadTimeout) { $downloadTimeout.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
    }
}

function Get-AssetSHA256 {
    <#
    Compute the downloaded manager digest using the platform PowerShell primitive.
    使用平台 PowerShell 原语计算已下载管理器的摘要。
    #>
    param([Parameter(Mandatory = $true)][string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-SafeTemporaryRoot {
    <#
    Resolve the user temporary root and reject reparse points before cleanup ownership is established.
    解析用户临时根目录，并在建立清理所有权前拒绝重解析点。
    #>
    param([Parameter(Mandatory = $true)][string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $info = [IO.DirectoryInfo]::new($fullPath)
    if (-not $info.Exists) {
        Stop-Bootstrap 'temporary root does not exist / 临时根目录不存在'
    }
    if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Stop-Bootstrap 'temporary root must not be a reparse point / 临时根目录不能是重解析点'
    }
    return $info.FullName
}

function Test-SafeTemporaryDirectory {
    <#
    Accept only this run's direct random child and reject reparse points before recursive removal.
    仅接受本次运行的随机直接子目录，并在递归删除前拒绝重解析点。
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Root
    )
    try {
        $rootFull = [IO.Path]::GetFullPath($Root)
        $candidateFull = [IO.Path]::GetFullPath($Path)
        $rootInfo = [IO.DirectoryInfo]::new($rootFull)
        if (-not $rootInfo.Exists) { return $false }
        if (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        $separator = [IO.Path]::DirectorySeparatorChar
        $rootPrefix = if ($rootFull.EndsWith([string]$separator)) { $rootFull } else { $rootFull + $separator }
        if (-not $candidateFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        $leaf = [IO.Path]::GetFileName($candidateFull)
        if ($leaf -notmatch '^vmmm-bootstrap-[0-9a-fA-F]{32}$') { return $false }
        $info = [IO.DirectoryInfo]::new($candidateFull)
        if (-not $info.Exists) { return $false }
        if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        return $true
    } catch {
        return $false
    }
}

function Remove-SafeTemporaryDirectory {
    <#
    Remove only an owned, validated bootstrap directory and leave unsafe paths untouched.
    仅删除已拥有且验证通过的引导目录，对不安全路径保持不动。
    #>
    param(
        [string] $Path,
        [string] $Root,
        [bool] $Owned
    )
    if (-not $Owned -or [string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return }
    if (-not (Test-SafeTemporaryDirectory -Path $Path -Root $Root)) { return }
    try {
        Remove-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Recurse -Force -ErrorAction Stop
    } catch {
        # Cleanup must never replace the manager's actual error or remove an unverified path.
        # 清理失败不能覆盖管理器原始错误，也不能删除未验证的路径。
    }
}

$tempRoot = $null
$tempDirectory = $null
$tempDirectoryCreated = $false
try {
    Assert-InjectedRelease

    if (-not $Source) { $Source = $env:VMMM_BOOTSTRAP_SOURCE }
    if (-not $ProxyPrefix) { $ProxyPrefix = $env:VMMM_BOOTSTRAP_PROXY_PREFIX }
    if (-not $Source) { $Source = 'official' }
    $prefix = Get-SourcePrefix -SelectedSource $Source -SelectedPrefix $ProxyPrefix
    $platformId = Get-PlatformId
    $assetName = $script:VMMMAssetNames[$platformId]
    $expectedSHA256 = $script:VMMMSHA256[$platformId].ToLowerInvariant()
    $assetPath = "https://github.com/$script:VMMMRepository/releases/download/$script:VMMMVersion/$assetName"
    $downloadUrl = "$prefix$assetPath"
    if ($downloadUrl -notmatch '^https://') {
        Stop-Bootstrap 'download URL is not HTTPS / 下载地址不是 HTTPS'
    }

    if ([Console]::IsInputRedirected) {
        Stop-Bootstrap 'an interactive terminal is required; download the manager first and run it directly / 需要交互式终端，请先下载管理器再直接运行'
    }
    if ([Console]::IsOutputRedirected) {
        Stop-Bootstrap 'a writable interactive terminal is required; run the manager directly / 需要可写的交互终端，请直接运行管理器'
    }
    if (-not [Environment]::UserInteractive) {
        Stop-Bootstrap 'an interactive Windows session is required / 需要交互式 Windows 会话'
    }

    $tempRoot = Get-SafeTemporaryRoot -Path ([IO.Path]::GetTempPath())
    $tempDirectory = [IO.Path]::GetFullPath((Join-Path $tempRoot ("vmmm-bootstrap-" + [Guid]::NewGuid().ToString('N'))))
    $existingTemporaryItem = Get-Item -LiteralPath $tempDirectory -Force -ErrorAction SilentlyContinue
    if ($null -ne $existingTemporaryItem -or [IO.File]::Exists($tempDirectory) -or [IO.Directory]::Exists($tempDirectory)) {
        Stop-Bootstrap 'temporary directory name already exists; refusing to clean it / 临时目录名称已存在，拒绝清理'
    }
    $null = New-Item -ItemType Directory -Path $tempDirectory -ErrorAction Stop
    $tempDirectoryCreated = $true
    if (-not (Test-SafeTemporaryDirectory -Path $tempDirectory -Root $tempRoot)) {
        Stop-Bootstrap 'temporary directory failed ownership validation / 临时目录所有权验证失败'
    }
    $managerPath = Join-Path $tempDirectory $assetName
    Download-SecureFile -Url $downloadUrl -Destination $managerPath
    $actualSHA256 = Get-AssetSHA256 -Path $managerPath
    if ($actualSHA256 -ne $expectedSHA256) {
        Stop-Bootstrap "manager SHA-256 mismatch for $platformId / $platformId 管理器 SHA-256 不匹配"
    }

    if ($ManagerArguments.Count -gt 0 -and $ManagerArguments[0] -eq '--') {
        if ($ManagerArguments.Count -eq 1) { $ManagerArguments = @() }
        else { $ManagerArguments = @($ManagerArguments[1..($ManagerArguments.Count - 1)]) }
    }
    # Scope bootstrap source metadata to the child process and restore the caller environment exactly.
    # 将引导来源元数据限定在子进程，并完整恢复调用方环境。
    $previousBootstrapSource = [Environment]::GetEnvironmentVariable('VMMM_BOOTSTRAP_SOURCE', [EnvironmentVariableTarget]::Process)
    $previousBootstrapPrefix = [Environment]::GetEnvironmentVariable('VMMM_BOOTSTRAP_PROXY_PREFIX', [EnvironmentVariableTarget]::Process)
    try {
        [Environment]::SetEnvironmentVariable('VMMM_BOOTSTRAP_SOURCE', $Source, [EnvironmentVariableTarget]::Process)
        [Environment]::SetEnvironmentVariable('VMMM_BOOTSTRAP_PROXY_PREFIX', $prefix, [EnvironmentVariableTarget]::Process)
        & $managerPath install @ManagerArguments
        $managerExitCode = $LASTEXITCODE
    } finally {
        [Environment]::SetEnvironmentVariable('VMMM_BOOTSTRAP_SOURCE', $previousBootstrapSource, [EnvironmentVariableTarget]::Process)
        [Environment]::SetEnvironmentVariable('VMMM_BOOTSTRAP_PROXY_PREFIX', $previousBootstrapPrefix, [EnvironmentVariableTarget]::Process)
    }
    if ($managerExitCode -ne 0) {
        Stop-Bootstrap "manager exited with code $managerExitCode / 管理器以代码 $managerExitCode 退出"
    }
} catch {
    [Console]::Error.WriteLine("$($_.Exception.Message)")
    exit 1
} finally {
    Remove-SafeTemporaryDirectory -Path $tempDirectory -Root $tempRoot -Owned $tempDirectoryCreated
}
