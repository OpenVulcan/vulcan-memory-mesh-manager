"""Cross-check Python packaging with the Go standard-library signer.
交叉验证 Python 打包流程与 Go 标准库签名器。
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import package_release


class SignManifestCrossTests(unittest.TestCase):
    """Ensure Python release output is signed and verified by Go crypto/ed25519.
    确保 Python 发行输出由 Go crypto/ed25519 完成签名和验签。
    """

    repository_root = Path(__file__).resolve().parents[1]
    seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

    def run_go_signer(self, *arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        """Run the Go signing CLI without shell interpolation.
        不经过 shell 插值运行 Go 签名 CLI。
        """

        return subprocess.run(
            ["go", "run", "./scripts/sign_manifest.go", *arguments],
            cwd=self.repository_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def make_inputs(self, root: Path) -> Path:
        """Create all five deterministic Python packaging inputs.
        创建五个平台的确定性 Python 打包输入。
        """

        input_dir = root / "input"
        input_dir.mkdir()
        for platform in package_release.PLATFORMS:
            input_dir.joinpath(package_release.input_name(platform)).write_bytes((platform + "\n").encode())
        return input_dir

    def test_python_package_cross_checks_with_go_signer(self) -> None:
        """Sign Python package_release output and verify it through the Go CLI.
        对 Python package_release 输出签名，并通过 Go CLI 验证。
        """

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release_dir = root / "release"
            package_release.package_release(self.make_inputs(root), release_dir, "v1.2.3", "a" * 40)
            environment = os.environ.copy()
            environment["VMMM_RELEASE_ED25519_PRIVATE_KEY"] = self.seed_hex
            environment["VMMM_RELEASE_ED25519_KEY_ID"] = "release-test"
            sign = self.run_go_signer(
                "sign",
                "--manifest",
                str(release_dir / "manifest.json"),
                "--signature",
                str(release_dir / "manifest.sig"),
                environment=environment,
            )
            self.assertEqual(sign.returncode, 0, sign.stderr)
            public = self.run_go_signer("public", environment=environment)
            self.assertEqual(public.returncode, 0, public.stderr)
            environment["VMMM_RELEASE_ED25519_PUBLIC_KEY"] = public.stdout.strip()
            verify = self.run_go_signer(
                "verify",
                "--manifest",
                str(release_dir / "manifest.json"),
                "--signature",
                str(release_dir / "manifest.sig"),
                environment=environment,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            package_release.verify_release(release_dir)

    def test_missing_secret_fails_closed(self) -> None:
        """Refuse Go signing when the private-key Secret is absent.
        缺少私钥 Secret 时拒绝 Go 签名。
        """

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_bytes(b"{}\n")
            environment = os.environ.copy()
            environment.pop("VMMM_RELEASE_ED25519_PRIVATE_KEY", None)
            environment["VMMM_RELEASE_ED25519_KEY_ID"] = "release-test"
            result = self.run_go_signer(
                "sign",
                "--manifest",
                str(manifest),
                "--signature",
                str(root / "manifest.sig"),
                environment=environment,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required signing secret", result.stderr)

    def test_tampered_manifest_fails_go_verification(self) -> None:
        """Reject a manifest modified after the Go signature was created.
        拒绝 Go 创建签名后被修改的清单。
        """

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            signature = root / "manifest.sig"
            manifest.write_bytes(b"original\n")
            environment = os.environ.copy()
            environment["VMMM_RELEASE_ED25519_PRIVATE_KEY"] = self.seed_hex
            environment["VMMM_RELEASE_ED25519_KEY_ID"] = "release-test"
            sign = self.run_go_signer(
                "sign",
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                environment=environment,
            )
            self.assertEqual(sign.returncode, 0, sign.stderr)
            public = self.run_go_signer("public", environment=environment)
            self.assertEqual(public.returncode, 0, public.stderr)
            environment["VMMM_RELEASE_ED25519_PUBLIC_KEY"] = public.stdout.strip()
            manifest.write_bytes(b"changed\n")
            verify = self.run_go_signer(
                "verify",
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                environment=environment,
            )
            self.assertNotEqual(verify.returncode, 0)
            self.assertIn("verification failed", verify.stderr)


if __name__ == "__main__":
    unittest.main()
