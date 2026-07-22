from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_phase4c_bilingual_docs_have_matching_status_structure() -> None:
    english = (ROOT / "docs/en/PHASE4C.md").read_text(encoding="utf-8")
    chinese = (ROOT / "docs/zh-CN/PHASE4C.md").read_text(encoding="utf-8")
    for shared in ("CSR", "CRL", "Staging", "2.3.0", "24", "Pending", "NO-GO"):
        assert shared in english
        assert shared in chinese
    assert english.count("| 0 |") == chinese.count("| 0 |")
    assert english.count("## ") == chinese.count("## ")


def test_nezha_benchmark_has_no_fabricated_runtime_values() -> None:
    for path in (
        ROOT / "docs/en/comparisons/NEZHA_BENCHMARK.md",
        ROOT / "docs/zh-CN/comparisons/NEZHA_BENCHMARK.md",
    ):
        text = path.read_text(encoding="utf-8")
        assert "Nezha 2.3.0" in text or "哪吒 2.3.0" in text
        assert text.count("Pending") >= 20
        assert "Running/Pending" in text


def test_crl_candidate_is_readable_before_nonroot_gateway_validation() -> None:
    script = (ROOT / "scripts/publish-agent-crl.sh").read_text(encoding="utf-8")
    readable = script.index('chmod 0644 "$candidate"')
    validation = script.index("docker compose exec -T agent-gateway")
    publication = script.index('mv -f "$candidate" "$active"')
    assert readable < validation < publication
