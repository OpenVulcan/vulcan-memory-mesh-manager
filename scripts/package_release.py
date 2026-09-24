"""Build and verify the standalone VMMM release assets.
构建并校验独立 VMMM 管理器发行资产。

The manager release is deliberately a set of single executable files. VMM
runtime archives are owned by the VMM repository and are never copied into
this release directory.
管理器发行版刻意使用一组单文件可执行程序。VMM 运行时压缩包由 VMM 仓库
负责，本脚本绝不会把它们复制到管理器发行目录。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable


# These are the five immutable platform IDs shared with internal/platform.
# 这些是与 internal/platform 共用的五个不可变平台标识。
PLATFORMS: dict[str, dict[str, str]] = {
    "windows-x64": {"input": "vmmm-windows-x64.exe", "suffix": ".exe"},
    "linux-x64": {"input": "vmmm-linux-x64", "suffix": ""},
    "linux-arm64": {"input": "vmmm-linux-arm64", "suffix": ""},
    "macos-intel": {"input": "vmmm-macos-intel", "suffix": ""},
    "macos-arm64": {"input": "vmmm-macos-arm64", "suffix": ""},
}

# The manifest protocol is intentionally smaller than the VMM package receipt.
# 该清单协议有意保持简单，并且不同于 VMM 包内清单。
MANIFEST_PROTOCOL_VERSION = 1
PRODUCT = "vmmm"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
# Bootstrap scripts are release conveniences and are not signed manager artifacts.
# 引导脚本是发行便利文件，不属于签名的管理器资产。
BOOTSTRAP_NAMES = {"install.ps1", "install.sh"}
TAG_PATTERN = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ReleaseError(ValueError):
    """Report a release input or verification failure.
    报告发行输入或校验失败。
    """


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys before validation.
    在校验前拒绝 JSON 对象中的重复键。
    """

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> dict[str, Any]:
    """Load one strict JSON object without accepting trailing content.
    读取一个严格 JSON 对象，不接受尾随内容。
    """

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, ReleaseError) as exc:
        raise ReleaseError(f"cannot read strict JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"{path} must contain a JSON object")
    return value


def _validate_tag(tag: str) -> str:
    """Validate the immutable semantic release tag used in asset names.
    校验用于资产名称的不可变语义版本标签。
    """

    if not isinstance(tag, str) or not TAG_PATTERN.fullmatch(tag):
        raise ReleaseError(f"invalid release tag: {tag!r}")
    return tag


def _validate_commit(commit: str) -> str:
    """Validate the exact lowercase Git commit recorded in the manifest.
    校验清单中记录的完整小写 Git 提交哈希。
    """

    if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
        raise ReleaseError("commit must be a 40-character lowercase hexadecimal SHA-1")
    return commit


def asset_name(tag: str, platform: str) -> str:
    """Return the canonical one-file release asset name.
    返回规范的单文件发行资产名称。
    """

    _validate_tag(tag)
    spec = PLATFORMS.get(platform)
    if spec is None:
        raise ReleaseError(f"unsupported release platform: {platform}")
    return f"vmmm-{tag}-{platform}{spec['suffix']}"


def input_name(platform: str) -> str:
    """Return the exact build artifact name expected from the workflow.
    返回工作流必须提供的精确构建资产名称。
    """

    spec = PLATFORMS.get(platform)
    if spec is None:
        raise ReleaseError(f"unsupported release platform: {platform}")
    return spec["input"]


def _sha256(path: Path) -> str:
    """Hash one regular file with bounded memory usage.
    以受限内存读取并计算一个普通文件的摘要。
    """

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ReleaseError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _regular_file(path: Path, description: str) -> None:
    """Require a non-symlink regular file at the supplied path.
    要求指定路径是非符号链接的普通文件。
    """

    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"{description} must be a regular file: {path}")


def _reject_runtime_files(names: Iterable[str]) -> None:
    """Reject VMM runtime names from the standalone manager output.
    拒绝独立管理器发行目录中出现 VMM 运行时文件名。
    """

    forbidden = {
        "vmm-local",
        "vmm-local.exe",
        "vmm-migrate",
        "vmm-migrate.exe",
        "vmm-pii-tester",
        "vmm-pii-tester.exe",
        "vulcan-memory-mesh",
    }
    for name in names:
        if name.lower() in forbidden or name.lower().startswith("vulcan-memory-mesh-"):
            raise ReleaseError(f"VMM runtime file is forbidden in a VMMM release: {name}")


def _manifest(tag: str, commit: str, artifacts: list[dict[str, Any]]) -> bytes:
    """Serialize the exact signed manifest bytes with stable field ordering.
    以稳定字段顺序序列化需要签名的精确清单字节。
    """

    value = {
        "protocol_version": MANIFEST_PROTOCOL_VERSION,
        "product": PRODUCT,
        "tag": _validate_tag(tag),
        "commit": _validate_commit(commit),
        "artifacts": artifacts,
    }
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")


def _validate_artifact_entry(entry: Any, tag: str, expected_platform: str | None = None) -> None:
    """Validate one signed artifact entry and its canonical filename.
    校验一个签名资产条目及其规范文件名。
    """

    if not isinstance(entry, dict) or set(entry) != {"platform", "filename", "bytes", "sha256"}:
        raise ReleaseError("artifact entry must contain exactly platform, filename, bytes, sha256")
    platform = entry["platform"]
    filename = entry["filename"]
    size = entry["bytes"]
    digest = entry["sha256"]
    if not isinstance(platform, str) or platform not in PLATFORMS:
        raise ReleaseError(f"unsupported artifact platform: {platform!r}")
    if expected_platform is not None and platform != expected_platform:
        raise ReleaseError(f"artifact platform {platform!r} does not match {expected_platform!r}")
    if not isinstance(filename, str) or filename != asset_name(tag, platform):
        raise ReleaseError(f"artifact filename for {platform} is not canonical: {filename!r}")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ReleaseError(f"artifact {filename} has an invalid byte count")
    if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
        raise ReleaseError(f"artifact {filename} has an invalid SHA-256")


def validate_manifest(value: Any) -> dict[str, Any]:
    """Validate the complete manager manifest protocol and return it.
    校验完整的管理器发行清单协议并返回清单对象。
    """

    if not isinstance(value, dict) or set(value) != {"protocol_version", "product", "tag", "commit", "artifacts"}:
        raise ReleaseError("manifest has an unexpected object shape")
    if type(value["protocol_version"]) is not int or value["protocol_version"] != MANIFEST_PROTOCOL_VERSION:
        raise ReleaseError(f"unsupported manifest protocol: {value['protocol_version']!r}")
    if value["product"] != PRODUCT:
        raise ReleaseError(f"unsupported manifest product: {value['product']!r}")
    tag = _validate_tag(value["tag"])
    commit = _validate_commit(value["commit"])
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(PLATFORMS):
        raise ReleaseError("manifest must contain exactly five platform artifacts")
    seen: set[str] = set()
    for entry in artifacts:
        _validate_artifact_entry(entry, tag)
        platform = entry["platform"]
        if platform in seen:
            raise ReleaseError(f"duplicate manifest platform: {platform}")
        seen.add(platform)
    if seen != set(PLATFORMS):
        raise ReleaseError(f"manifest platform set is incomplete: {sorted(seen)}")
    return {"protocol_version": value["protocol_version"], "product": value["product"], "tag": tag, "commit": commit, "artifacts": artifacts}


def package_release(input_dir: Path, output_dir: Path, tag: str, commit: str) -> Path:
    """Copy five verified manager binaries and write manifest.json.
    复制五个平台的已校验管理器程序并写入 manifest.json。
    """

    _validate_tag(tag)
    _validate_commit(commit)
    if not input_dir.is_dir():
        raise ReleaseError(f"input directory does not exist: {input_dir}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReleaseError(f"cannot create output directory {output_dir}: {exc}") from exc
    existing_output = list(output_dir.iterdir())
    if existing_output:
        raise ReleaseError(f"output directory must be empty: {output_dir}")

    expected_inputs = {input_name(platform) for platform in PLATFORMS}
    actual_files = [entry.name for entry in input_dir.iterdir() if entry.is_file() or entry.is_symlink()]
    _reject_runtime_files(actual_files)
    unexpected = sorted(set(actual_files) - expected_inputs)
    if unexpected:
        raise ReleaseError(f"input directory contains unexpected files: {unexpected}")

    artifacts: list[dict[str, Any]] = []
    for platform in PLATFORMS:
        source = input_dir / input_name(platform)
        _regular_file(source, f"build artifact for {platform}")
        destination = output_dir / asset_name(tag, platform)
        if destination.exists() or destination.is_symlink():
            raise ReleaseError(f"refusing to overwrite release asset: {destination}")
        try:
            shutil.copyfile(source, destination)
        except OSError as exc:
            raise ReleaseError(f"cannot copy {source} to {destination}: {exc}") from exc
        artifacts.append(
            {
                "platform": platform,
                "filename": destination.name,
                "bytes": destination.stat().st_size,
                "sha256": _sha256(destination),
            }
        )

    manifest_path = output_dir / MANIFEST_NAME
    if manifest_path.exists() or manifest_path.is_symlink():
        raise ReleaseError(f"refusing to overwrite manifest: {manifest_path}")
    manifest_bytes = _manifest(tag, commit, artifacts)
    try:
        manifest_path.write_bytes(manifest_bytes)
    except OSError as exc:
        raise ReleaseError(f"cannot write manifest {manifest_path}: {exc}") from exc
    validate_manifest(json.loads(manifest_bytes, object_pairs_hook=_reject_duplicate_keys))
    return manifest_path


def verify_release(output_dir: Path, manifest_path: Path | None = None) -> None:
    """Verify manifest identity, every asset size/hash, and release contents.
    校验清单身份、每个资产的大小与摘要以及发行目录内容。
    """

    if not output_dir.is_dir():
        raise ReleaseError(f"release directory does not exist: {output_dir}")
    manifest_path = manifest_path or (output_dir / MANIFEST_NAME)
    _regular_file(manifest_path, "manifest")
    value = validate_manifest(_load_json(manifest_path))
    required = {MANIFEST_NAME, SIGNATURE_NAME} | {entry["filename"] for entry in value["artifacts"]}
    # Detached Linux signatures are verified with the committed OpenPGP trust root.
    # Linux 分离式签名使用仓库固定的 OpenPGP 信任根另行验证。
    allowed = required | BOOTSTRAP_NAMES | {
        entry["filename"] + ".asc" for entry in value["artifacts"] if entry["platform"].startswith("linux-")
    }
    actual = {entry.name for entry in output_dir.iterdir() if entry.is_file() or entry.is_symlink()}
    _reject_runtime_files(actual)
    unexpected = sorted(actual - allowed)
    missing = sorted(required - actual)
    if unexpected:
        raise ReleaseError(f"release directory contains unexpected files: {unexpected}")
    if missing:
        raise ReleaseError(f"release directory is missing files: {missing}")
    for entry in value["artifacts"]:
        path = output_dir / entry["filename"]
        _regular_file(path, f"release artifact {entry['filename']}")
        if path.stat().st_size != entry["bytes"]:
            raise ReleaseError(f"size mismatch for {entry['filename']}")
        if _sha256(path) != entry["sha256"]:
            raise ReleaseError(f"SHA-256 mismatch for {entry['filename']}")


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser for package and verify operations.
    构建 package 与 verify 操作的命令行解析器。
    """

    parser = argparse.ArgumentParser(description="Package and verify VMMM release assets.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    package_parser = subparsers.add_parser("package", help="copy binaries and write manifest.json")
    package_parser.add_argument("--input-dir", type=Path, required=True)
    package_parser.add_argument("--output-dir", type=Path, required=True)
    package_parser.add_argument("--tag", required=True)
    package_parser.add_argument("--commit", required=True)
    verify_parser = subparsers.add_parser("verify", help="verify a signed release directory")
    verify_parser.add_argument("--release-dir", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one release packaging command and return a process status.
    执行一个发行打包命令并返回进程状态码。
    """

    args = _parser().parse_args(argv)
    try:
        if args.command == "package":
            package_release(args.input_dir, args.output_dir, args.tag, args.commit)
        else:
            verify_release(args.release_dir, args.manifest)
    except ReleaseError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
