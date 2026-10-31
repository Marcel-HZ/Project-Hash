"""Markdown 文档生成器：汇总各步骤的讲解、代码、示例输出。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from context import get_password, get_sample


@dataclass
class StepSection:
    """单个步骤的文档片段。"""
    number: int
    title: str
    lecture: str
    code: str
    sample_output: str


class MarkdownBuilder:
    """累积步骤内容并生成最终 Markdown。"""

    def __init__(self) -> None:
        self._sections: list[StepSection] = []

    def add_section(self, section: StepSection) -> None:
        self._sections.append(section)

    def _build_overview(self) -> str:
        """生成本次运行的总览表（明文 + 各步骤关键数据）。"""
        pwd = get_password()
        lines = [
            "## 本次运行总览",
            "",
            f"- **演示明文**: `{pwd}`",
            f"- **明文长度**: {len(pwd)} 字符",
        ]

        # 尝试提取各步骤的关键数据
        sha256_sample = get_sample(1, "")
        if sha256_sample and "SHA-256 Hex:" in sha256_sample:
            hex_val = sha256_sample.split("SHA-256 Hex:")[1].split()[0]
            lines.append(f"- **SHA-256 Hex**: `{hex_val}`")

        salt_sample = get_sample(3, "")
        if salt_sample and "无盐 SHA-256:" in salt_sample:
            no_salt = salt_sample.split("无盐 SHA-256:")[1].splitlines()[0].strip()
            lines.append(f"- **无盐 SHA-256**: `{no_salt}`")

        lines.append("")
        lines.append("---")
        lines.append("")
        return "\n".join(lines)

    def build(self) -> str:
        lines: list[str] = []
        lines.append("# 加密过程及解析\n")
        lines.append("## 目录\n")
        for s in self._sections:
            anchor = f"{s.number}-{s.title}".replace(" ", "-").lower()
            lines.append(f"{s.number}. [{s.title}](#{anchor})")
        lines.append("")
        lines.append("---\n")

        # 总览
        overview = self._build_overview()
        lines.append(overview)

        for s in self._sections:
            anchor = f"{s.number}-{s.title}".replace(" ", "-").lower()
            lines.append(f"## {s.number}. {s.title}")
            lines.append(f"<a id=\"{anchor}\"></a>")
            lines.append("")
            lines.append("### 原理讲解")
            lines.append("")
            lines.append("> " + "\n> ".join(s.lecture.splitlines()))
            lines.append("")
            lines.append("### 核心代码")
            lines.append("")
            lines.append("```python")
            lines.append(s.code.rstrip())
            lines.append("```")
            lines.append("")
            lines.append("### 运行示例")
            lines.append("")
            lines.append("")
            lines.append(s.sample_output.rstrip())
            lines.append("")
            lines.append("---\n")

        return "\n".join(lines)


def generate_guide(sections: list[StepSection], output_path: str | Path = "HASH_DEMO_GUIDE.md") -> str:
    """生成并写入 Markdown 指南，返回文件路径。"""
    builder = MarkdownBuilder()
    for s in sections:
        builder.add_section(s)
    content = builder.build()
    path = Path(output_path)
    path.write_text(content, encoding="utf-8")
    return str(path.resolve())