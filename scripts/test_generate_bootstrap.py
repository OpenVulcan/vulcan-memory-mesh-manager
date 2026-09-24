#!/usr/bin/env python3
# These tests protect the release metadata boundary and bootstrap URL contract.
# 这些测试保护发行元数据边界与引导下载地址契约。

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


# SCRIPT_DIR points tests at the templates owned by this script package.
# SCRIPT_DIR 将测试指向本脚本包负责的模板目录。
SCRIPT_DIR = Path(__file__).resolve().parent
# MODULE_SPEC and MODULE load the generator without changing the repository import path.
# MODULE_SPEC 与 MODULE 在不修改仓库导入路径的情况下加载生成器。
MODULE_SPEC = importlib.util.spec_from_file_location(
    "generate_bootstrap", SCRIPT_DIR / "generate_bootstrap.py"
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
MODULE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(MODULE)

# DIGEST and DIGESTS provide deterministic test metadata without pretending to be release values.
# DIGEST 与 DIGESTS 提供确定性测试元数据，不冒充正式发行摘要。
DIGEST = "a" * 64
DIGESTS = {platform: DIGEST for platform in MODULE.PLATFORMS}


class BootstrapGeneratorTests(unittest.TestCase):
    """Verify fail-closed generation and deterministic five-platform metadata.
    验证失败关闭生成行为和确定性的五平台元数据。
    """

    def test_replacements_cover_every_platform(self) -> None:
        """Every platform receives a deterministic filename and digest marker.
        每个平台都得到确定性的文件名和摘要标记。
        """
        table = MODULE.replacements("v0.2.0", DIGESTS)
        self.assertEqual(
            table["__VMMM_ASSET_WINDOWS_X64__"],
            "vmmm-v0.2.0-windows-x64.exe",
        )
        self.assertEqual(table["__VMMM_SHA256_MACOS_ARM64__"], DIGEST)
        self.assertEqual(len([key for key in table if "SHA256" in key]), 5)

    def test_missing_digest_fails_closed(self) -> None:
        """A release cannot render with a missing platform digest.
        缺少任一平台摘要时不能生成发行脚本。
        """
        with self.assertRaises(MODULE.BootstrapGenerationError):
            MODULE.parse_sha256([f"{platform}={DIGEST}" for platform in MODULE.PLATFORMS[:-1]])
        with self.assertRaises(MODULE.BootstrapGenerationError):
            MODULE.replacements("v0.2.0", {platform: DIGEST for platform in MODULE.PLATFORMS[:-1]})

    def test_invalid_version_and_digest_are_rejected(self) -> None:
        """URL path injection and incomplete digests are rejected.
        URL 路径注入和不完整摘要都会被拒绝。
        """
        with self.assertRaises(MODULE.BootstrapGenerationError):
            MODULE.validate_version("v0.2.0/evil")
        with self.assertRaises(MODULE.BootstrapGenerationError):
            MODULE.parse_sha256([f"{platform}=not-a-digest" for platform in MODULE.PLATFORMS])

    def test_unknown_template_marker_is_rejected(self) -> None:
        """A template with an unknown marker cannot silently ship.
        含未知标记的模板不能静默进入发行物。
        """
        table = MODULE.replacements("v0.2.0", DIGESTS)
        with self.assertRaises(MODULE.BootstrapGenerationError):
            MODULE.render_template("__VMMM_VERSION__ __VMMM_UNKNOWN__", table)

    def test_generate_keeps_templates_and_makes_shell_executable(self) -> None:
        """Generation writes a separate directory and marks install.sh executable.
        生成过程写入独立目录并为 install.sh 设置可执行权限。
        """
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "release"
            ps1, sh = MODULE.generate(
                version="v0.2.0",
                digests=DIGESTS,
                template_dir=SCRIPT_DIR,
                output_dir=output_dir,
            )
            self.assertTrue(ps1.is_file())
            self.assertTrue(sh.is_file())
            self.assertTrue((SCRIPT_DIR / "install.ps1").read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertTrue(ps1.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertIn("vmmm-v0.2.0-linux-x64", sh.read_text(encoding="utf-8"))
            self.assertNotIn("__VMMM_", ps1.read_text(encoding="utf-8"))
            if os.name != 'nt':
                self.assertTrue(sh.stat().st_mode & stat.S_IXUSR)
            else:
                # A deliberately unsupported source proves PowerShell 5.1 parsed the whole rendered script without downloading.
                # 故意使用不支持的来源，以证明 PowerShell 5.1 已解析整个发行脚本且未进入下载。
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-File", str(ps1), "-Source", "unavailable-test-source"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsupported source", result.stdout + result.stderr)
                template_result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-File", str(SCRIPT_DIR / "install.ps1")],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                self.assertNotEqual(template_result.returncode, 0)
                self.assertIn("no valid injected release version", template_result.stdout + template_result.stderr)
            self.assertIn("__VMMM_", (SCRIPT_DIR / "install.sh").read_text(encoding="utf-8"))

    def test_generation_cannot_overwrite_template_directory(self) -> None:
        """The release renderer cannot destroy its own fail-closed templates.
        发行渲染器不能销毁自身的失败关闭模板。
        """
        with self.assertRaises(MODULE.BootstrapGenerationError):
            MODULE.generate(
                version="v0.2.0",
                digests=DIGESTS,
                template_dir=SCRIPT_DIR,
                output_dir=SCRIPT_DIR,
            )

    def test_generated_powershell_resolves_real_github_asset_urls(self) -> None:
        """Evaluate the generated script's actual URL assignments for every supported source without downloading.
        不进行下载，直接执行生成脚本的真实 URL 赋值，覆盖每种受支持来源。
        """
        engines = [engine for name in ("pwsh", "powershell.exe") if (engine := shutil.which(name))]
        if not engines:
            self.skipTest("PowerShell is required for the generated URL contract")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ps1, _ = MODULE.generate(version="v0.2.0", digests=DIGESTS, template_dir=SCRIPT_DIR, output_dir=root / "release")
            harness = root / "inspect-url.ps1"
            # Parse trusted source and execute only declarations plus the two actual URL assignments.
            # 解析受信源码，仅执行声明及两个实际 URL 赋值，不触发下载、终端或清理操作。
            harness.write_text(r'''
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Generated script is not valid PowerShell' }
foreach ($statement in $tree.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $statement.Extent.Text
    } elseif ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
              $statement.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
              $statement.Left.VariablePath.UserPath.StartsWith('script:VMMM')) {
        Invoke-Expression $statement.Extent.Text
    }
}
$assignments = @($tree.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
    $node.Left.VariablePath.UserPath -in @('assetPath', 'downloadUrl')
}, $true))
if ($assignments.Count -ne 2) { throw 'Expected exactly two production URL assignments' }
$assetName = $script:VMMMAssetNames['windows-x64']
$urls = @{}
foreach ($source in @('official', 'ghproxy-net', 'gh-proxy-org', 'ghfast-top', 'custom')) {
    $customPrefix = ''
    if ($source -eq 'custom') { $customPrefix = 'https://mirror.example/github/' }
    $prefix = Get-SourcePrefix -SelectedSource $source -SelectedPrefix $customPrefix
    foreach ($assignment in $assignments) { Invoke-Expression $assignment.Extent.Text }
    $urls[$source] = $downloadUrl
}
$urls | ConvertTo-Json -Compress
''', encoding="utf-8-sig")
            official = "https://github.com/OpenVulcan/vulcan-memory-mesh-manager/releases/download/v0.2.0/vmmm-v0.2.0-windows-x64.exe"
            expected = {
                "official": official,
                "ghproxy-net": "https://ghproxy.net/" + official,
                "gh-proxy-org": "https://gh-proxy.org/" + official,
                "ghfast-top": "https://ghfast.top/" + official,
                "custom": "https://mirror.example/github/" + official,
            }
            for engine in engines:
                with self.subTest(engine=engine):
                    result = subprocess.run([engine, "-NoProfile", "-File", str(harness), str(ps1)], capture_output=True, encoding="utf-8", errors="replace", timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(json.loads(result.stdout), expected)

    def test_templates_are_manager_only_and_tty_guarded(self) -> None:
        """Templates only target the manager repository and require a terminal.
        模板只指向管理器仓库并要求交互式终端。
        """
        shell = (SCRIPT_DIR / "install.sh").read_text(encoding="utf-8")
        powershell = (SCRIPT_DIR / "install.ps1").read_text(encoding="utf-8")
        for content in (shell, powershell):
            self.assertIn("vulcan-memory-mesh-manager", content)
            self.assertNotIn("vulcan-memory-mesh/releases", content)
        self.assertIn("/dev/tty", shell)
        self.assertIn("IsInputRedirected", powershell)
        self.assertIn("IsOutputRedirected", powershell)
        self.assertIn("switch -CaseSensitive ($SelectedSource)", powershell)
        self.assertIn("Get-FileHash", powershell)
        # Cleanup assertions prove that only an owned, resolved random directory can be removed.
        # 清理断言证明只有本次拥有且解析通过的随机目录才会被删除。
        self.assertIn("temp_dir_created=0", shell)
        self.assertIn("temp_child_prefix", shell)
        self.assertIn("temp_original_tmpdir_set", shell)
        self.assertIn("unset TMPDIR", shell)
        self.assertIn('temp_dir_real=$(CDPATH= cd -P "$tmp_dir"', shell)
        self.assertIn('[ ! -L "$temp_root_real" ]', shell)
        self.assertIn('[ ! -L "$tmp_dir" ]', shell)
        self.assertIn('rm -rf "$temp_dir_real"', shell)
        self.assertNotIn('rm -rf "$tmp_dir"', shell)
        self.assertIn("Get-SafeTemporaryRoot", powershell)
        self.assertIn("Test-SafeTemporaryDirectory", powershell)
        self.assertIn("$rootInfo = [IO.DirectoryInfo]::new($rootFull)", powershell)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", powershell)
        self.assertIn("$tempDirectoryCreated = $false", powershell)
        self.assertIn("New-Item -ItemType Directory -Path", powershell)
        self.assertIn(
            "Remove-SafeTemporaryDirectory -Path $tempDirectory -Root $tempRoot -Owned $tempDirectoryCreated",
            powershell,
        )
        self.assertNotIn("Remove-Item -LiteralPath $tempDirectory -Recurse", powershell)

    def test_bootstrap_downloads_have_a_hard_size_limit(self) -> None:
        """Both bootstrap templates reject oversized proxy responses before executing the manager.
        两种引导模板都在执行管理器前拒绝过大的代理响应。
        """
        shell = (SCRIPT_DIR / "install.sh").read_text(encoding="utf-8")
        powershell = (SCRIPT_DIR / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("--max-filesize \"$max_manager_bytes\"", shell)
        self.assertIn("(ulimit -f 1048576 && curl", shell)
        self.assertIn('download_size=$(wc -c < "$manager_path"', shell)
        self.assertIn('[ "$download_size" -le "$max_manager_bytes" ]', shell)
        self.assertIn("$script:MaxManagerBytes = [long]536870912", powershell)
        self.assertIn("$response.Content.Headers.ContentLength", powershell)
        self.assertIn("$inputStream.ReadAsync($buffer, 0, $buffer.Length, $downloadTimeout.Token)", powershell)
        self.assertIn("$client.GetAsync($current, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $downloadTimeout.Token)", powershell)
        self.assertIn("$script:MaxManagerBytes - $received", powershell)

    def test_bootstrap_source_is_scoped_to_manager_child(self) -> None:
        """Pass the selected source to vmmm without exporting it or evaluating user text.
        将选定来源传给 vmmm 子进程，不导出到调用方，也不执行用户文本。
        """

        shell = (SCRIPT_DIR / "install.sh").read_text(encoding="utf-8")
        powershell = (SCRIPT_DIR / "install.ps1").read_text(encoding="utf-8")
        self.assertIn(
            'VMMM_BOOTSTRAP_SOURCE="$source_id" VMMM_BOOTSTRAP_PROXY_PREFIX="$proxy_prefix" "$trusted_path" install',
            shell,
        )
        self.assertNotIn('"$manager_path" install', shell)
        self.assertIn('cp "$source_path" "$trusted_path"', shell)
        self.assertIn('[ "$actual_digest" = "$expected_digest" ]', shell)
        self.assertNotIn("export VMMM_BOOTSTRAP_SOURCE", shell)
        self.assertNotIn("export VMMM_BOOTSTRAP_PROXY_PREFIX", shell)
        self.assertIn(
            "SetEnvironmentVariable('VMMM_BOOTSTRAP_SOURCE', $Source, [EnvironmentVariableTarget]::Process)",
            powershell,
        )
        self.assertIn(
            "SetEnvironmentVariable('VMMM_BOOTSTRAP_PROXY_PREFIX', $prefix, [EnvironmentVariableTarget]::Process)",
            powershell,
        )
        self.assertIn("$previousBootstrapSource", powershell)
        self.assertIn("$previousBootstrapPrefix", powershell)
        self.assertIn("finally", powershell)
        self.assertNotIn("Invoke-Expression", powershell)
        self.assertNotIn("eval ", shell)


if __name__ == "__main__":
    unittest.main()
