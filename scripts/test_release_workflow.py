"""Test release identity binding in the GitHub Actions workflow.
测试 GitHub Actions 工作流中的发行标签身份绑定。
"""

from __future__ import annotations

import unittest
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


# WORKFLOW_TEXT is the review target for the release identity protocol.
# WORKFLOW_TEXT 是发行身份协议的静态审核目标。
WORKFLOW_TEXT = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml").read_text(
    encoding="utf-8"
)


def resolve_peeled_commit(ls_remote_output: str, tag: str) -> str:
    """Resolve an annotated or lightweight tag from git ls-remote output.
    从 git ls-remote 输出解析附注标签或轻量标签的提交。
    """

    direct = ""
    peeled = ""
    for line in ls_remote_output.splitlines():
        if not line.strip():
            continue
        object_id, ref = line.split("\t", 1)
        if ref == f"refs/tags/{tag}^{{}}":
            peeled = object_id
        elif ref == f"refs/tags/{tag}":
            direct = object_id
    return peeled or direct


def select_existing_tag_commit(ls_remote_output: str, tag: str, requested: str = "") -> str:
    """Model the fail-closed existing-tag commit selection used by the workflow.
    模拟工作流对已存在标签采用的失败关闭式提交选择逻辑。
    """

    selected = resolve_peeled_commit(ls_remote_output, tag)
    if not selected:
        raise ValueError("tag does not exist")
    if requested and requested != selected:
        raise ValueError("requested commit does not match the tag")
    return selected


class ReleaseWorkflowIdentityTests(unittest.TestCase):
    """Protect tag resolution, race handling, and manifest identity checks.
    保护标签解析、竞态处理和清单身份一致性检查。
    """

    def test_annotated_tag_prefers_peeled_commit(self) -> None:
        """An annotated tag must build its peeled commit instead of its tag object.
        附注标签必须构建剥离后的提交，而不是标签对象本身。
        """

        tag = "v1.2.3"
        tag_object = "a" * 40
        commit = "b" * 40
        output = f"{tag_object}\trefs/tags/{tag}\n{commit}\trefs/tags/{tag}^{{}}\n"
        self.assertEqual(resolve_peeled_commit(output, tag), commit)
        self.assertEqual(select_existing_tag_commit(output, tag), commit)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires native Bash")
    def test_version_check_bash_syntax(self) -> None:
        """Parse the actual version-check script to reject broken heredocs and unclosed conditionals.
        解析真实版本检查脚本，拒绝错误的内嵌文本边界和未闭合条件分支。
        """
        start = WORKFLOW_TEXT.index("      - name: Verify embedded release identity")
        start = WORKFLOW_TEXT.index("        run: |\n", start) + len("        run: |\n")
        end = WORKFLOW_TEXT.index("      - name:", start)
        script = "\n".join(line[10:] for line in WORKFLOW_TEXT[start:end].splitlines())
        checked = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires native Bash")
    def test_verification_mode_rejects_noncanonical_versions(self) -> None:
        """Execute verification-mode resolution without credentials, tags, or remote mutation.
        在没有凭据、标签和远端修改的情况下，实际运行验证模式的身份解析。
        """
        start = WORKFLOW_TEXT.index("      - name: Resolve immutable release identity")
        start = WORKFLOW_TEXT.index("        run: |\n", start) + len("        run: |\n")
        end = WORKFLOW_TEXT.index("\n  build:", start)
        script = "\n".join(line[10:] for line in WORKFLOW_TEXT[start:end].splitlines())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            for tag, expected in (("v0.1.0", 0), ("v0.1.0-rc.1", 0), ("v00.1.0", 1), ("v0.1.0-..", 1)):
                output.write_text("", encoding="utf-8")
                env = dict(os.environ, VERIFY_ONLY="true", EVENT_TAG=tag, EVENT_COMMIT="a" * 40,
                           EVENT_COMMIT_INPUT="", GITHUB_OUTPUT=str(output))
                checked = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
                with self.subTest(tag=tag):
                    self.assertEqual(checked.returncode, expected, checked.stderr)
                    self.assertEqual("commit=" in output.read_text(), expected == 0)

    def test_lightweight_tag_uses_direct_commit(self) -> None:
        """A lightweight tag has only its direct commit reference.
        轻量标签只有直接提交引用。
        """

        tag = "v1.2.4"
        commit = "c" * 40
        output = f"{commit}\trefs/tags/{tag}\n"
        self.assertEqual(resolve_peeled_commit(output, tag), commit)

    def test_existing_tag_commit_mismatch_fails_closed(self) -> None:
        """A manual commit cannot override an existing remote tag.
        手工提交不能覆盖已存在的远程标签提交。
        """

        tag = "v1.2.5"
        commit = "d" * 40
        with self.assertRaises(ValueError):
            select_existing_tag_commit(f"{commit}\trefs/tags/{tag}\n", tag, "e" * 40)

    def test_workflow_contains_immutable_identity_guards(self) -> None:
        """Static checks keep the workflow protocol reviewable without GitHub credentials.
        静态检查让工作流协议无需 GitHub 凭据即可审核。
        """

        required_fragments = (
            "fetch-depth: 0",
            "EVENT_COMMIT_INPUT",
            "git ls-remote --tags origin",
            'refs/tags/${tag}^{}',
            "tag_exists=",
            "TAG_WAS_PRESENT",
            'manifest_commit" == "$RELEASE_COMMIT"',
            "gh api --method POST",
            'ref=refs/tags/${RELEASE_TAG}',
            'sha=${RELEASE_COMMIT}',
            "--verify-tag",
            "-buildvcs=true",
            '-ldflags "-X main.version=${RELEASE_TAG}"',
            'go version -m "$RUNNER_TEMP/$RELEASE_INPUT"',
            'vcs.revision=${RELEASE_COMMIT}',
            '"$RUNNER_TEMP/$RELEASE_INPUT" --json version',
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, WORKFLOW_TEXT)
        self.assertNotIn('--target "$RELEASE_COMMIT"', WORKFLOW_TEXT)


if __name__ == "__main__":
    unittest.main()
