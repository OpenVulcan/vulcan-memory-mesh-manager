"""Test the standalone VMMM release package contract.
测试独立 VMMM 管理器发行打包契约。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import package_release


class PackageReleaseTests(unittest.TestCase):
    """Exercise canonical assets, hashes, and forbidden runtime inputs.
    验证规范资产、摘要以及被禁止的运行时输入。
    """

    def make_inputs(self, root: Path) -> Path:
        """Create deterministic manager-only build inputs.
        创建确定性的仅管理器构建输入。
        """

        input_dir = root / "input"
        input_dir.mkdir()
        for platform in package_release.PLATFORMS:
            input_dir.joinpath(package_release.input_name(platform)).write_bytes((platform + "\n").encode())
        return input_dir

    def test_package_and_verify_all_five_assets(self) -> None:
        """Package all five assets and verify exact manifest fields.
        打包五个平台资产并校验清单字段。
        """

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir = self.make_inputs(root)
            release_dir = root / "release"
            manifest_path = package_release.package_release(input_dir, release_dir, "v1.2.3", "a" * 40)
            (release_dir / package_release.SIGNATURE_NAME).write_bytes(b"test signature")
            package_release.verify_release(release_dir)
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(value["product"], "vmmm")
            self.assertEqual(value["tag"], "v1.2.3")
            self.assertEqual({entry["platform"] for entry in value["artifacts"]}, set(package_release.PLATFORMS))
            self.assertEqual(
                {path.name for path in release_dir.iterdir()},
                {
                    package_release.MANIFEST_NAME,
                    package_release.SIGNATURE_NAME,
                    *(package_release.asset_name("v1.2.3", platform) for platform in package_release.PLATFORMS),
                },
            )

    def test_package_rejects_vmm_runtime_input(self) -> None:
        """Reject a VMM runtime file before any manager release is created.
        在创建管理器发行版前拒绝 VMM 运行时文件。
        """

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir = self.make_inputs(root)
            input_dir.joinpath("vmm-local").write_bytes(b"forbidden")
            with self.assertRaises(package_release.ReleaseError):
                package_release.package_release(input_dir, root / "release", "v1.2.3", "a" * 40)

    def test_verify_rejects_tampered_asset(self) -> None:
        """Reject a size or digest change after manifest generation.
        拒绝清单生成后发生的大小或摘要变化。
        """

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir = self.make_inputs(root)
            release_dir = root / "release"
            package_release.package_release(input_dir, release_dir, "v1.2.3", "a" * 40)
            (release_dir / package_release.SIGNATURE_NAME).write_bytes(b"test signature")
            (release_dir / package_release.asset_name("v1.2.3", "linux-x64")).write_bytes(b"tampered")
            with self.assertRaises(package_release.ReleaseError):
                package_release.verify_release(release_dir)

    def test_manifest_type_errors_are_reported_as_release_errors(self) -> None:
        """Reject non-string identities without leaking a parser traceback.
        拒绝非字符串身份字段，并以发行错误返回而不是抛出解析堆栈。
        """

        with self.assertRaises(package_release.ReleaseError):
            package_release.validate_manifest(
                {
                    "protocol_version": 1,
                    "product": "vmmm",
                    "tag": ["v1.2.3"],
                    "commit": "a" * 40,
                    "artifacts": [],
                }
            )

    def test_manifest_boolean_protocol_version_is_rejected(self) -> None:
        """Reject JSON booleans that Python would otherwise compare equal to one.
        拒绝 Python 中可能与数字一比较相等的 JSON 布尔值。
        """

        with self.assertRaises(package_release.ReleaseError):
            package_release.validate_manifest(
                {
                    "protocol_version": True,
                    "product": "vmmm",
                    "tag": "v1.2.3",
                    "commit": "a" * 40,
                    "artifacts": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
