#!/bin/sh
# This script downloads one signed-by-digest VMMM manager release and starts its installer.
# 此脚本只下载由摘要固定的 VMMM 管理器发行物并启动其安装命令。

set -eu
umask 077

# The release generator replaces every marker before a script can be published.
# 发布生成器会在脚本发布前替换所有标记；模板状态必须保持失败关闭。
VMMM_REPOSITORY='OpenVulcan/vulcan-memory-mesh-manager'
VMMM_VERSION='__VMMM_VERSION__'
VMMM_ASSET_WINDOWS_X64='__VMMM_ASSET_WINDOWS_X64__'
VMMM_ASSET_LINUX_X64='__VMMM_ASSET_LINUX_X64__'
VMMM_ASSET_LINUX_ARM64='__VMMM_ASSET_LINUX_ARM64__'
VMMM_ASSET_MACOS_INTEL='__VMMM_ASSET_MACOS_INTEL__'
VMMM_ASSET_MACOS_ARM64='__VMMM_ASSET_MACOS_ARM64__'
VMMM_SHA256_WINDOWS_X64='__VMMM_SHA256_WINDOWS_X64__'
VMMM_SHA256_LINUX_X64='__VMMM_SHA256_LINUX_X64__'
VMMM_SHA256_LINUX_ARM64='__VMMM_SHA256_LINUX_ARM64__'
VMMM_SHA256_MACOS_INTEL='__VMMM_SHA256_MACOS_INTEL__'
VMMM_SHA256_MACOS_ARM64='__VMMM_SHA256_MACOS_ARM64__'

# Fail when a release artifact was not injected by the trusted release process.
# 如果可信发布流程没有注入发行物信息，则立即失败而不尝试猜测版本或摘要。
fail() {
    printf '%s\n' "vmmm bootstrap: $*" >&2
    exit 1
}

is_hex_sha256() {
    value=$1
    [ "${#value}" -eq 64 ] || return 1
    case "$value" in
        *[!0123456789abcdefABCDEF]*) return 1 ;;
    esac
}

is_safe_asset_name() {
    value=$1
    [ -n "$value" ] || return 1
    case "$value" in
        .|..) return 1 ;;
        */*|*\\*|*' '*|*'	'*|*'\r'*|*'\n'*) return 1 ;;
        *[!A-Za-z0-9._-]*) return 1 ;;
    esac
}

is_safe_version() {
    value=$1
    [ -n "$value" ] || return 1
    case "$value" in
        __VMMM_*|*/*|*\\*|*' '*|*'	'*|*'\r'*|*'\n'*) return 1 ;;
        v[0-9A-Za-z]*) return 0 ;;
        *) return 1 ;;
    esac
}

validate_injected_release() {
    is_safe_version "$VMMM_VERSION" || fail 'the bootstrap template has no valid injected release version / 引导脚本没有有效的注入版本'
    is_safe_asset_name "$VMMM_ASSET_WINDOWS_X64" || fail 'windows-x64 asset metadata is not injected / 未注入 windows-x64 资产信息'
    is_safe_asset_name "$VMMM_ASSET_LINUX_X64" || fail 'linux-x64 asset metadata is not injected / 未注入 linux-x64 资产信息'
    is_safe_asset_name "$VMMM_ASSET_LINUX_ARM64" || fail 'linux-arm64 asset metadata is not injected / 未注入 linux-arm64 资产信息'
    is_safe_asset_name "$VMMM_ASSET_MACOS_INTEL" || fail 'macos-intel asset metadata is not injected / 未注入 macos-intel 资产信息'
    is_safe_asset_name "$VMMM_ASSET_MACOS_ARM64" || fail 'macos-arm64 asset metadata is not injected / 未注入 macos-arm64 资产信息'
    is_hex_sha256 "$VMMM_SHA256_WINDOWS_X64" || fail 'windows-x64 SHA-256 is not injected / 未注入 windows-x64 SHA-256'
    is_hex_sha256 "$VMMM_SHA256_LINUX_X64" || fail 'linux-x64 SHA-256 is not injected / 未注入 linux-x64 SHA-256'
    is_hex_sha256 "$VMMM_SHA256_LINUX_ARM64" || fail 'linux-arm64 SHA-256 is not injected / 未注入 linux-arm64 SHA-256'
    is_hex_sha256 "$VMMM_SHA256_MACOS_INTEL" || fail 'macos-intel SHA-256 is not injected / 未注入 macos-intel SHA-256'
    is_hex_sha256 "$VMMM_SHA256_MACOS_ARM64" || fail 'macos-arm64 SHA-256 is not injected / 未注入 macos-arm64 SHA-256'
}

# Validate a user-controlled HTTPS proxy prefix before concatenating the fixed GitHub URL.
# 在拼接固定 GitHub 地址前校验用户输入的 HTTPS 代理前缀。
validate_proxy_prefix() {
    prefix=$1
    case "$prefix" in
        https://*) ;;
        *) fail 'custom proxy prefix must start with https:// / 自定义代理前缀必须以 https:// 开头' ;;
    esac
    case "$prefix" in
        */) ;;
        *) fail 'custom proxy prefix must end with / / 自定义代理前缀必须以 / 结尾' ;;
    esac
    case "$prefix" in
        *'?'*|*'#'*|*'@'*|*' '*|*'	'*|*'\r'*|*'\n'*|*'\\'*)
            fail 'custom proxy prefix contains a forbidden URL character / 自定义代理前缀包含禁止的 URL 字符'
            ;;
    esac
    authority=${prefix#https://}
    host=${authority%%/*}
    [ -n "$host" ] || fail 'custom proxy prefix has no host / 自定义代理前缀缺少主机名'
    [ "$authority" != "$host" ] || fail 'custom proxy prefix must include a path slash / 自定义代理前缀必须包含路径斜杠'
    case "$host" in
        -*|.*|*..*|*[!A-Za-z0-9.:[\]-]*)
            fail 'custom proxy prefix host is invalid / 自定义代理前缀主机名无效'
            ;;
    esac
}

# Select only the exact source IDs documented by the release contract.
# 只选择发行契约中明确列出的源 ID。
source_id=${VMMM_BOOTSTRAP_SOURCE:-official}
proxy_prefix=${VMMM_BOOTSTRAP_PROXY_PREFIX:-}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source)
            [ "$#" -ge 2 ] || fail '--source requires a value / --source 需要参数'
            source_id=$2
            shift 2
            ;;
        --source=*)
            source_id=${1#--source=}
            shift
            ;;
        --proxy-prefix)
            [ "$#" -ge 2 ] || fail '--proxy-prefix requires a value / --proxy-prefix 需要参数'
            proxy_prefix=$2
            shift 2
            ;;
        --proxy-prefix=*)
            proxy_prefix=${1#--proxy-prefix=}
            shift
            ;;
        --)
            shift
            break
            ;;
        --help|-h)
            printf '%s\n' 'Usage: install.sh [--source official|ghproxy-net|gh-proxy-org|ghfast-top|custom] [--proxy-prefix https://...] [-- manager arguments...]'
            printf '%s\n' '用法：install.sh [--source ...] [--proxy-prefix https://...] [-- 管理器参数...]'
            exit 0
            ;;
        *)
            fail "unknown bootstrap option: $1 / 未知引导脚本参数：$1"
            ;;
    esac
done

validate_injected_release

case "$source_id" in
    official)
        [ -z "$proxy_prefix" ] || fail 'official source cannot use a proxy prefix / 官方源不能同时使用代理前缀'
        proxy_prefix=''
        ;;
    ghproxy-net)
        [ -z "$proxy_prefix" ] || fail 'built-in source cannot use a custom prefix / 内置源不能同时使用自定义前缀'
        proxy_prefix='https://ghproxy.net/'
        ;;
    gh-proxy-org)
        [ -z "$proxy_prefix" ] || fail 'built-in source cannot use a custom prefix / 内置源不能同时使用自定义前缀'
        proxy_prefix='https://gh-proxy.org/'
        ;;
    ghfast-top)
        [ -z "$proxy_prefix" ] || fail 'built-in source cannot use a custom prefix / 内置源不能同时使用自定义前缀'
        proxy_prefix='https://ghfast.top/'
        ;;
    custom)
        [ -n "$proxy_prefix" ] || fail 'custom source requires --proxy-prefix or VMMM_BOOTSTRAP_PROXY_PREFIX / 自定义源需要 --proxy-prefix 或环境变量'
        validate_proxy_prefix "$proxy_prefix"
        ;;
    *)
        fail "unsupported source: $source_id / 不支持的下载源：$source_id"
        ;;
esac

os_name=$(uname -s 2>/dev/null || true)
arch_name=$(uname -m 2>/dev/null || true)
case "$os_name:$arch_name" in
    Linux:x86_64|Linux:amd64) platform_id=linux-x64; asset_name=$VMMM_ASSET_LINUX_X64; expected_sha256=$VMMM_SHA256_LINUX_X64 ;;
    Linux:aarch64|Linux:arm64) platform_id=linux-arm64; asset_name=$VMMM_ASSET_LINUX_ARM64; expected_sha256=$VMMM_SHA256_LINUX_ARM64 ;;
    Darwin:x86_64|Darwin:amd64) platform_id=macos-intel; asset_name=$VMMM_ASSET_MACOS_INTEL; expected_sha256=$VMMM_SHA256_MACOS_INTEL ;;
    Darwin:arm64|Darwin:aarch64) platform_id=macos-arm64; asset_name=$VMMM_ASSET_MACOS_ARM64; expected_sha256=$VMMM_SHA256_MACOS_ARM64 ;;
    *) fail "unsupported platform: $os_name/$arch_name / 不支持的平台：$os_name/$arch_name" ;;
esac

# Build the URL only from the fixed repository, tag, and generated asset name.
# 只使用固定仓库、版本和生成的资产名构造下载地址。
asset_path="https://github.com/$VMMM_REPOSITORY/releases/download/$VMMM_VERSION/$asset_name"
if [ -n "$proxy_prefix" ]; then
    download_url="$proxy_prefix$asset_path"
else
    download_url=$asset_path
fi
case "$download_url" in
    https://*) ;;
    *) fail 'download URL is not HTTPS / 下载地址不是 HTTPS' ;;
esac

command -v curl >/dev/null 2>&1 || fail 'curl is required / 需要 curl'

# Keep the manager outside the source tree and remove it after the child exits.
# Resolve and own a private random temporary directory before downloading.
# 在下载前解析并拥有一个本次运行专用的随机临时目录。
temp_root_input=${TMPDIR:-/tmp}
case "$temp_root_input" in
    /*) ;;
    *) fail 'TMPDIR must be an absolute directory / TMPDIR 必须是绝对目录' ;;
esac
if [ "$temp_root_input" != "/" ]; then
    temp_root_input=${temp_root_input%/}
fi
[ -d "$temp_root_input" ] || fail 'TMPDIR is not a directory / TMPDIR 不是目录'
[ ! -L "$temp_root_input" ] || fail 'TMPDIR must not be a symbolic link / TMPDIR 不能是符号链接'
temp_root_real=$(CDPATH= cd -P "$temp_root_input" && pwd -P) || fail 'cannot resolve TMPDIR / 无法解析 TMPDIR'
[ -d "$temp_root_real" ] || fail 'resolved TMPDIR is not a directory / 解析后的 TMPDIR 不是目录'
[ ! -L "$temp_root_real" ] || fail 'resolved TMPDIR must not be a symbolic link / 解析后的 TMPDIR 不能是符号链接'
if [ "$temp_root_real" = "/" ]; then
    temp_child_prefix="/vmmm-bootstrap."
else
    temp_child_prefix="$temp_root_real/vmmm-bootstrap."
fi
temp_dir_created=0
temp_dir_real=''
temp_original_tmpdir_set=${TMPDIR+x}
temp_original_tmpdir=${TMPDIR-}
TMPDIR=$temp_root_real
# 将管理器放在临时目录中，并在子进程退出后清理。
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/vmmm-bootstrap.XXXXXX") || fail 'cannot create a temporary directory / 无法创建临时目录'
if [ "$temp_original_tmpdir_set" = x ]; then
    TMPDIR=$temp_original_tmpdir
else
    unset TMPDIR
fi
cleanup() {
    if [ "$temp_dir_created" -ne 1 ] || [ -z "$temp_dir_real" ]; then
        return
    fi
    case "$temp_dir_real" in
        "$temp_child_prefix"[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
        *) return ;;
    esac
    [ -d "$temp_root_real" ] || return
    [ ! -L "$temp_root_real" ] || return
    [ -d "$temp_dir_real" ] || return
    [ ! -L "$temp_dir_real" ] || return
    rm -rf "$temp_dir_real"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
temp_dir_created=1
temp_dir_real=$(CDPATH= cd -P "$tmp_dir" && pwd -P) || fail 'cannot resolve temporary directory / 无法解析临时目录'
[ "$temp_dir_real" != "$temp_root_real" ] || fail 'temporary directory escaped its root / 临时目录越过了预期根目录'
[ ! -L "$tmp_dir" ] || fail 'temporary directory must not be a symbolic link / 临时目录不能是符号链接'
case "$temp_dir_real" in
    "$temp_child_prefix"[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
    *) fail 'temporary directory is outside the expected root / 临时目录不在预期根目录内' ;;
esac
manager_path="$temp_dir_real/$asset_name"

curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 2 --retry-delay 1 --connect-timeout 15 --max-time 600 --output "$manager_path" "$download_url" || fail 'manager download failed / 管理器下载失败'

calculate_sha256() {
    target=$1
    if command -v sha256sum >/dev/null 2>&1; then
        digest_line=$(sha256sum "$target") || return 1
        printf '%s\n' "${digest_line%% *}"
        return 0
    fi
    if command -v shasum >/dev/null 2>&1; then
        digest_line=$(shasum -a 256 "$target") || return 1
        printf '%s\n' "${digest_line%% *}"
        return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
        digest_line=$(openssl dgst -sha256 "$target") || return 1
        digest_line=${digest_line##*= }
        printf '%s\n' "$digest_line"
        return 0
    fi
    return 1
}

actual_sha256=$(calculate_sha256 "$manager_path") || fail 'no SHA-256 utility found (sha256sum, shasum, or openssl) / 找不到 SHA-256 工具（sha256sum、shasum 或 openssl）'
case "$actual_sha256" in
    *[!0123456789abcdefABCDEF]*) fail 'SHA-256 utility returned an invalid digest / SHA-256 工具返回了无效摘要' ;;
esac
[ "$actual_sha256" = "$expected_sha256" ] || fail "manager SHA-256 mismatch for $platform_id / $platform_id 管理器 SHA-256 不匹配"

[ -r /dev/tty ] || fail 'an interactive terminal is required; download the manager first and run it directly / 需要交互式终端，请先下载管理器再直接运行'
[ -w /dev/tty ] || fail 'the terminal is not writable; run the manager directly / 终端不可写，请直接运行管理器'
chmod u+x "$manager_path" 2>/dev/null || fail 'cannot mark the manager executable / 无法设置管理器可执行权限'

# Promote the pinned binary into a root-owned private directory and verify the copied
# bytes before execution. Root never executes the user-writable download path.
# 将固定摘要的程序复制进 root 私有目录并重新验证，root 绝不执行用户可写的下载路径。
run_privileged_manager() {
    /bin/sh -c '
        set -eu
        umask 077
        PATH=/usr/bin:/bin
        export PATH
        source_path=$1
        expected_digest=$2
        source_id=$3
        proxy_prefix=$4
        shift 4
        trusted_dir=$(mktemp -d /tmp/vmmm-bootstrap-root.XXXXXX) || exit 1
        trap '\''rm -rf "$trusted_dir"'\'' EXIT
        trap '\''exit 130'\'' HUP INT TERM
        trusted_path="$trusted_dir/vmmm"
        cp "$source_path" "$trusted_path" || exit 1
        chmod 0700 "$trusted_path" || exit 1
        if command -v sha256sum >/dev/null 2>&1; then
            digest_line=$(sha256sum "$trusted_path") || exit 1
            actual_digest=${digest_line%% *}
        elif command -v shasum >/dev/null 2>&1; then
            digest_line=$(shasum -a 256 "$trusted_path") || exit 1
            actual_digest=${digest_line%% *}
        elif command -v openssl >/dev/null 2>&1; then
            digest_line=$(openssl dgst -sha256 "$trusted_path") || exit 1
            actual_digest=${digest_line##*= }
        else
            printf "%s\n" "vmmm bootstrap: no SHA-256 utility for privileged copy / 特权副本缺少 SHA-256 校验工具" >&2
            exit 1
        fi
        [ "$actual_digest" = "$expected_digest" ] || {
            printf "%s\n" "vmmm bootstrap: privileged copy SHA-256 mismatch / 特权副本 SHA-256 不匹配" >&2
            exit 1
        }
        VMMM_BOOTSTRAP_SOURCE="$source_id" VMMM_BOOTSTRAP_PROXY_PREFIX="$proxy_prefix" "$trusted_path" install "$@" </dev/tty
    ' vmmm-root "$manager_path" "$expected_sha256" "$source_id" "$proxy_prefix" "$@"
}

# Read TUI input from the controlling terminal when this script came through a pipe.
# 脚本通过管道进入时，从控制终端读取 TUI 输入，避免管道内容占用 stdin。
if [ "$(id -u)" -eq 0 ]; then
    run_privileged_manager "$@"
else
    [ -x /usr/bin/sudo ] || fail 'sudo is required for system installation / 系统安装需要 sudo'
    /usr/bin/sudo -k -- /bin/sh -c '
        set -eu
        umask 077
        PATH=/usr/bin:/bin
        export PATH
        source_path=$1
        expected_digest=$2
        source_id=$3
        proxy_prefix=$4
        shift 4
        trusted_dir=$(mktemp -d /tmp/vmmm-bootstrap-root.XXXXXX) || exit 1
        trap '\''rm -rf "$trusted_dir"'\'' EXIT
        trap '\''exit 130'\'' HUP INT TERM
        trusted_path="$trusted_dir/vmmm"
        cp "$source_path" "$trusted_path" || exit 1
        chmod 0700 "$trusted_path" || exit 1
        if command -v sha256sum >/dev/null 2>&1; then
            digest_line=$(sha256sum "$trusted_path") || exit 1
            actual_digest=${digest_line%% *}
        elif command -v shasum >/dev/null 2>&1; then
            digest_line=$(shasum -a 256 "$trusted_path") || exit 1
            actual_digest=${digest_line%% *}
        elif command -v openssl >/dev/null 2>&1; then
            digest_line=$(openssl dgst -sha256 "$trusted_path") || exit 1
            actual_digest=${digest_line##*= }
        else
            printf "%s\n" "vmmm bootstrap: no SHA-256 utility for privileged copy / 特权副本缺少 SHA-256 校验工具" >&2
            exit 1
        fi
        [ "$actual_digest" = "$expected_digest" ] || {
            printf "%s\n" "vmmm bootstrap: privileged copy SHA-256 mismatch / 特权副本 SHA-256 不匹配" >&2
            exit 1
        }
        VMMM_BOOTSTRAP_SOURCE="$source_id" VMMM_BOOTSTRAP_PROXY_PREFIX="$proxy_prefix" "$trusted_path" install "$@" </dev/tty
    ' vmmm-root "$manager_path" "$expected_sha256" "$source_id" "$proxy_prefix" "$@"
fi
