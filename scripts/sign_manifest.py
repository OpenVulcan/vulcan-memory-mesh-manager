"""Delegate manifest signing to the Go standard-library implementation.
将清单签名委托给 Go 标准库实现。

This compatibility entry point contains no cryptographic implementation. It
keeps existing Python release commands usable while the actual Ed25519 work
is performed by scripts/sign_manifest.go and crypto/ed25519.
此兼容入口不包含任何密码学实现。它保留已有 Python 发行命令的可用性，
实际 Ed25519 运算由 scripts/sign_manifest.go 和 crypto/ed25519 完成。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    """Run the audited Go signing CLI without invoking a shell.
    不经过 shell 调用已审计的 Go 签名 CLI。
    """

    script_path = Path(__file__).resolve().with_suffix(".go")
    arguments = list(sys.argv[1:] if argv is None else argv)
    command = ["go", "run", str(script_path), *arguments]
    completed = subprocess.run(command, cwd=script_path.parent.parent, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
