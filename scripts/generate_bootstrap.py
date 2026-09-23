#!/usr/bin/env python3
"""Render release bootstrap scripts from fail-closed templates.
从失败关闭的模板渲染发行版引导脚本。
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterable, Mapping


# These platform IDs and their order are part of the bootstrap release contract.
# 这些平台 ID 及其顺序属于引导脚本发行契约。
PLATFORMS = (
    "windows-x64",
    "linux-x64",
    "linux-arm64",
    "macos-intel",
    "macos-arm64",
)


class BootstrapGenerationError(ValueError):
    """Describe invalid release metadata or unsafe template output.
    描述无效发行元数据或不安全模板输出。
    """


def asset_name(version: str, platform: str) -> str:
    """Return the deterministic manager filename for one release platform.
    返回某个发行平台对应的确定性管理器文件名。
    """
    if platform not in PLATFORMS:
        raise BootstrapGenerationError(f"unsupported platform: {platform}")
    suffix = ".exe" if platform == "windows-x64" else ""
    return f"vmmm-{version}-{platform}{suffix}"


def validate_version(version: str) -> str:
    """Validate a version tag before putting it into a URL path.
    在把版本标签写入 URL 路径前进行校验。
    """
    if not re.fullmatch(
        r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?",
        version,
    ):
        raise BootstrapGenerationError(
            "version must start with v and contain only release-safe characters"
        )
    return version


def parse_sha256(values: Iterable[str]) -> dict[str, str]:
    """Parse one complete SHA-256 assignment for every supported platform.
    解析每个受支持平台的一条完整 SHA-256 赋值。
    """
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise BootstrapGenerationError(
                f"SHA-256 must use PLATFORM=DIGEST syntax: {item}"
            )
        platform, digest = item.split("=", 1)
        if platform not in PLATFORMS:
            raise BootstrapGenerationError(f"unsupported platform: {platform}")
        if platform in result:
            raise BootstrapGenerationError(f"duplicate SHA-256 platform: {platform}")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise BootstrapGenerationError(
                f"SHA-256 for {platform} must be exactly 64 hexadecimal characters"
            )
        result[platform] = digest.lower()
    missing = [platform for platform in PLATFORMS if platform not in result]
    if missing:
        raise BootstrapGenerationError(
            "missing SHA-256 values for: " + ", ".join(missing)
        )
    return result


def replacements(version: str, digests: Mapping[str, str]) -> dict[str, str]:
    """Build the complete marker replacement table for both script templates.
    为两个脚本模板生成完整的标记替换表。
    """
    version = validate_version(version)
    if set(digests) != set(PLATFORMS):
        missing = sorted(set(PLATFORMS) - set(digests))
        extra = sorted(set(digests) - set(PLATFORMS))
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("unsupported=" + ",".join(extra))
        raise BootstrapGenerationError("invalid digest platform set: " + "; ".join(details))
    normalized = parse_sha256(
        f"{platform}={digests[platform]}" for platform in PLATFORMS
    )
    result = {"__VMMM_VERSION__": version}
    for platform in PLATFORMS:
        marker_platform = platform.upper().replace("-", "_")
        result[f"__VMMM_ASSET_{marker_platform}__"] = asset_name(version, platform)
        result[f"__VMMM_SHA256_{marker_platform}__"] = normalized[platform]
    return result


def render_template(template: str, replacement_table: Mapping[str, str]) -> str:
    """Replace every known marker and reject any unreplaced VMMM marker.
    替换所有已知标记，并拒绝残留的 VMMM 标记。
    """
    rendered = template
    for marker, value in replacement_table.items():
        if marker not in rendered:
            raise BootstrapGenerationError(f"template is missing marker: {marker}")
        rendered = rendered.replace(marker, value)
    leftover = re.findall(r"__VMMM_[A-Z0-9_]+__", rendered)
    if leftover:
        raise BootstrapGenerationError(
            "template contains unknown or unreplaced markers: " + ", ".join(sorted(set(leftover)))
        )
    return rendered


def _atomic_write(path: Path, contents: str, mode: int) -> None:
    """Atomically write generated text and preserve the shell executable bit.
    原子写入生成文本，并保留 shell 脚本的可执行权限位。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def generate(
    *,
    version: str,
    digests: Mapping[str, str],
    template_dir: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Render both bootstrap scripts into a separate release directory.
    将两个引导脚本渲染到独立的发行目录。
    """
    template_dir = template_dir.resolve()
    output_dir = output_dir.resolve()
    if template_dir == output_dir:
        raise BootstrapGenerationError(
            "output directory must differ from template directory"
        )
    table = replacements(version, digests)
    outputs: list[Path] = []
    for filename in ("install.ps1", "install.sh"):
        template_path = template_dir / filename
        if not template_path.is_file():
            raise BootstrapGenerationError(f"missing template: {template_path}")
        rendered = render_template(
            template_path.read_text(encoding="utf-8"), table
        )
        mode = stat.S_IMODE(template_path.stat().st_mode)
        if filename == "install.sh":
            mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        output_path = output_dir / filename
        _atomic_write(output_path, rendered, mode)
        outputs.append(output_path)
    return outputs[0], outputs[1]


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser used by the release workflow.
    创建发行工作流使用的命令行参数解析器。
    """
    parser = argparse.ArgumentParser(
        description="Render fail-closed VMMM bootstrap scripts."
    )
    parser.add_argument("--version", required=True, help="release tag, for example v0.2.0")
    parser.add_argument(
        "--sha256",
        "--checksum",
        dest="sha256",
        action="append",
        default=[],
        metavar="PLATFORM=DIGEST",
        help="one complete SHA-256 assignment; repeat for all five platforms",
    )
    script_dir = Path(__file__).resolve().parent
    parser.add_argument("--template-dir", type=Path, default=script_dir)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Render scripts and return a shell-friendly process status.
    渲染脚本并返回适合 shell 使用的进程状态码。
    """
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        digests = parse_sha256(arguments.sha256)
        outputs = generate(
            version=arguments.version,
            digests=digests,
            template_dir=arguments.template_dir,
            output_dir=arguments.output_dir,
        )
    except (BootstrapGenerationError, OSError) as error:
        parser.error(str(error))
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
