"""Markdown 文档生成器：汇总各步骤的讲解、代码、示例输出。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from context import get_password, get_sample, get_trace


@dataclass
class StepSection:
    number: int
    title: str
    lecture: str
    code: str
    sample_output: str


class MarkdownBuilder:
    def __init__(self) -> None:
        self._sections: list[StepSection] = []

    def add_section(self, section: StepSection) -> None:
        self._sections.append(section)

    def _build_overview(self) -> str:
        pwd = get_password()
        lines = [
            "## 本次运行总览",
            "",
            f"- **演示明文**: `{pwd}`",
            f"- **明文长度**: {len(pwd)} 字符",
        ]
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

    def _trace_block(self, trace: dict, mode: str) -> str:
        lines = []
        lines.append(f"- **原始消息**: `{trace['original_message']!r}`")
        lines.append(f"- **原始长度**: {trace['original_len']} 字节")
        lines.append(f"- **填充后长度**: {trace['padded_len']} 字节")
        lines.append(f"- **分组数**: {trace['num_blocks']}")
        lines.append("- **初始状态**: " + " ".join(f"{h:08x}" for h in trace["initial_h"]))
        lines.append(f"- **最终摘要**: `{trace['final_digest'].hex()}`")
        for bt in trace["block_traces"]:
            lines.append(f"\n#### 消息块 {bt['block_index']}")
            lines.append("- 初始状态: " + " ".join(f"{h:08x}" for h in bt["initial_h"]))
            lines.append("- 最终状态: " + " ".join(f"{h:08x}" for h in bt["result_h"]))
            if mode == "full":
                lines.append("\n##### 消息调度 W[0..63]")
                lines.append("| i | W_i |")
                lines.append("|---|---|")
                for i, w in enumerate(bt["message_schedule"]):
                    lines.append(f"| {i} | {w:08x} |")
                lines.append("\n##### 64 轮压缩")
                lines.append("| Round | a | b | c | d | e | f | g | h | Wt | Kt | Σ0 | Σ1 | Ch | Maj | T1 | T2 | a' | e' |")
                lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
                for rs in bt["round_states"]:
                    lines.append(
                        f"| {rs['round']} | {rs['a']:08x} | {rs['b']:08x} | {rs['c']:08x} | {rs['d']:08x} | "
                        f"{rs['e']:08x} | {rs['f']:08x} | {rs['g']:08x} | {rs['h']:08x} | {rs['w']:08x} | {rs['k']:08x} | "
                        f"{rs['sigma0']:08x} | {rs['sigma1']:08x} | {rs['ch']:08x} | {rs['maj']:08x} | {rs['t1']:08x} | {rs['t2']:08x} | "
                        f"{rs['a_new']:08x} | {rs['e_new']:08x} |"
                    )
        return "\n".join(lines)

    def build(self, mode: str = "concise") -> str:
        lines: list[str] = []
        lines.append("# 加密过程及解析\n")
        lines.append("## 目录\n")
        for s in self._sections:
            anchor = f"{s.number}-{s.title}".replace(" ", "-").lower()
            lines.append(f"{s.number}. [{s.title}](#{anchor})")
        lines.append("")
        lines.append("---\n")

        overview = self._build_overview()
        lines.append(overview)

        trace = get_trace()
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
            lines.append(s.sample_output.rstrip())
            if s.number == 1 and trace:
                lines.append("")
                lines.append("#### SHA-256 计算过程")
                lines.append(self._trace_block(trace, mode))
            lines.append("")
            lines.append("---\n")

        return "\n".join(lines)


def generate_guide(sections, output_path="HASH_DEMO_GUIDE.md", mode: str = "concise") -> str:
    builder = MarkdownBuilder()
    for s in sections:
        builder.add_section(s)
    content = builder.build(mode=mode)
    path = Path(output_path)
    path.write_text(content, encoding="utf-8")
    return str(path.resolve())