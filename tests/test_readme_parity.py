from __future__ import annotations

from pathlib import Path
import re
import struct


ROOT = Path(__file__).resolve().parents[1]
ENGLISH = ROOT / "README.md"
CHINESE = ROOT / "README.zh-CN.md"

EXPECTED_HEADINGS = [
    "project-status",
    "features",
    "limitations",
    "architecture",
    "quick-install",
    "agent-enrollment",
    "dashboard-access",
    "backup-restore",
    "security-design",
    "roadmap",
    "contributing",
    "license",
]

HEADING_MAP = {
    "Project status": "project-status",
    "项目状态": "project-status",
    "Features": "features",
    "功能": "features",
    "Current limitations": "limitations",
    "当前限制": "limitations",
    "Architecture": "architecture",
    "架构": "architecture",
    "Quick install": "quick-install",
    "快速安装": "quick-install",
    "Agent enrollment": "agent-enrollment",
    "Agent 注册": "agent-enrollment",
    "Dashboard access": "dashboard-access",
    "Dashboard 访问": "dashboard-access",
    "Backup and restore": "backup-restore",
    "备份与恢复": "backup-restore",
    "Security design": "security-design",
    "安全设计": "security-design",
    "Roadmap": "roadmap",
    "路线图": "roadmap",
    "Contributing": "contributing",
    "贡献方式": "contributing",
    "License": "license",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def headings(markdown: str) -> list[tuple[int, str]]:
    return [
        (len(match.group(1)), HEADING_MAP.get(match.group(2), match.group(2)))
        for match in re.finditer(r"^(#{1,6})\s+(.+)$", markdown, re.MULTILINE)
    ]


def fenced_blocks(markdown: str) -> list[tuple[str, str]]:
    return re.findall(r"```([^\n]*)\n(.*?)```", markdown, re.DOTALL)


def section_shapes(markdown: str) -> list[tuple[int, int, int]]:
    sections = re.split(r"^##\s+.+$", markdown, flags=re.MULTILINE)[1:]
    return [
        (
            len(re.findall(r"^-\s+", section, re.MULTILINE)),
            len(re.findall(r"^\|", section, re.MULTILINE)),
            len(re.findall(r"\[[^]]+\]\([^)]+\)", section)),
        )
        for section in sections
    ]


def normalized_links(markdown: str) -> list[str]:
    targets = re.findall(r"\[[^]]+\]\(([^)]+)\)", markdown)
    return sorted(
        target.replace("docs/zh-CN/", "docs/LANG/")
        .replace("docs/en/", "docs/LANG/")
        .replace("dashboard-zh-CN.png", "dashboard-LANG.png")
        .replace("dashboard-en.png", "dashboard-LANG.png")
        for target in targets
    )


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return struct.unpack(">II", data[16:24])


def test_readmes_have_identical_structure() -> None:
    english = read(ENGLISH)
    chinese = read(CHINESE)

    assert headings(english) == headings(chinese)
    assert [name for _, name in headings(english)[1:]] == EXPECTED_HEADINGS
    assert section_shapes(english) == section_shapes(chinese)
    assert fenced_blocks(english) == fenced_blocks(chinese)
    assert normalized_links(english) == normalized_links(chinese)


def test_readmes_have_matching_badges_and_desktop_screenshots() -> None:
    english = read(ENGLISH)
    chinese = read(CHINESE)

    badge_pattern = r"\[!\[[^]]+\]\(([^)]+)\)\]\(([^)]+)\)"
    assert re.findall(badge_pattern, english) == re.findall(badge_pattern, chinese)
    english_size = png_size(ROOT / "docs/assets/dashboard-en.png")
    chinese_size = png_size(ROOT / "docs/assets/dashboard-zh-CN.png")
    assert english_size == chinese_size
    assert english_size[0] == 1440
    assert english_size[1] >= 1000


def test_readmes_use_the_same_install_commands() -> None:
    shell_blocks_en = [body for language, body in fenced_blocks(read(ENGLISH)) if language == "sh"]
    shell_blocks_zh = [body for language, body in fenced_blocks(read(CHINESE)) if language == "sh"]
    assert shell_blocks_en == shell_blocks_zh
