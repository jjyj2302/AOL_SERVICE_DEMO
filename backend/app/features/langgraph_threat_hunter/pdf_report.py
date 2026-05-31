"""시뮬레이션 결과 → PDF 리포트 생성기 (reportlab 기반).

엔드포인트 GET /api/lg/simulate/{scenario_id}/report.pdf 에서 호출되어
한 페이지 분량의 SOC 분석 보고서를 생성한다.

구성:
- 표지: 시나리오 제목 + IoC + 분석 일시
- 메트릭: 자동화 등급 / 신뢰도 / 처리 시간 / 휴먼 승인 여부
- 6 에이전트 출력 요약 (Orchestrator routing / Triage / Malware / Infra / Campaign)
- 산출물: 방화벽 차단 규칙 + 헌팅 가설 + Executive Summary
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---- 한글 폰트 등록 (시스템 의존성 없이 reportlab 내장 CID 폰트 사용) ----
try:
    pdfmetrics.registerFont(UnicodeCIDFont("HeiseiMin-W3"))   # 한자/한글 일부
    pdfmetrics.registerFont(UnicodeCIDFont("HYSMyeongJo-Medium"))
    KOR_FONT = "HYSMyeongJo-Medium"
except Exception:
    KOR_FONT = "Helvetica"


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "TitleKR",
            parent=base["Title"],
            fontName=KOR_FONT,
            fontSize=18,
            spaceAfter=4,
            textColor=colors.HexColor("#1F2937"),
        ),
        "subtitle": ParagraphStyle(
            "SubtitleKR",
            parent=base["Normal"],
            fontName=KOR_FONT,
            fontSize=10,
            textColor=colors.HexColor("#6B7280"),
            spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "H2KR",
            parent=base["Heading2"],
            fontName=KOR_FONT,
            fontSize=12,
            textColor=colors.HexColor("#1F2937"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "BodyKR",
            parent=base["Normal"],
            fontName=KOR_FONT,
            fontSize=9.5,
            leading=14,
            spaceAfter=3,
        ),
        "mono": ParagraphStyle(
            "MonoKR",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#374151"),
        ),
        "tag": ParagraphStyle(
            "TagKR",
            parent=base["Normal"],
            fontName=KOR_FONT,
            fontSize=9,
            textColor=colors.HexColor("#4F46E5"),
        ),
    }


def _metric_table(
    level: str | None,
    score: float | None,
    elapsed_ms: int | None,
    approval: bool | None,
    before_minutes: int | None,
):
    score_str = f"{(score or 0) * 100:.1f}%"
    data = [
        ["자동화 등급", "신뢰도", "처리 시간", "휴먼 승인"],
        [
            level or "-",
            score_str,
            f"{elapsed_ms or 0} ms",
            "필수" if approval else "불필요",
        ],
        [
            "L0=권고, L4=자동차단",
            "0~100%",
            f"Before: {before_minutes or '-'} 분 (수동)",
            "핵심자산/L4 시 필수",
        ],
    ]
    tbl = Table(data, colWidths=[40 * mm, 40 * mm, 45 * mm, 40 * mm])
    tbl.setStyle(
        TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), KOR_FONT),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, 1), 14),
            ("FONTSIZE", (0, 2), (-1, 2), 7.5),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#6B7280")),
            ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 2), (-1, 2), colors.HexColor("#9CA3AF")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F4F6")),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    return tbl


def generate_report_pdf(scenario_id: str, run_result: dict[str, Any]) -> bytes:
    """`run_result` 는 /api/lg/simulate/{id} 의 response body.

    반환값은 PDF 바이트.
    """
    styles = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title=f"AOL Threat Hunter — {scenario_id}",
    )

    story: list = []
    title = run_result.get("title") or f"Scenario {scenario_id}"
    findings = run_result.get("findings", {}) or {}
    deliverables = run_result.get("deliverables", {}) or {}
    ledger = run_result.get("audit_ledger", []) or []

    triage = findings.get("triage") or {}
    malware = findings.get("malware") or {}
    infra = findings.get("infrastructure") or {}
    campaign = findings.get("campaign") or {}

    # ---- 헤더 ----
    story.append(Paragraph(f"🛡️ AI Threat Hunter — {scenario_id}", styles["title"]))
    story.append(Paragraph(title, styles["subtitle"]))
    story.append(Paragraph(
        f"분석 일시: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ·  "
        f"실행 모드: simulation  ·  LangGraph + MCP Tool Mesh",
        styles["body"],
    ))
    story.append(Spacer(1, 6))

    # ---- 메트릭 표 ----
    story.append(_metric_table(
        run_result.get("automation_level"),
        run_result.get("confidence_score"),
        run_result.get("elapsed_ms"),
        run_result.get("human_approval_required"),
        deliverables.get("before_minutes"),
    ))
    story.append(Spacer(1, 10))

    # ---- 에이전트별 요약 ----
    story.append(Paragraph("🤖 Agent Outputs", styles["h2"]))

    if triage.get("chat_message") or triage.get("notes"):
        story.append(Paragraph(
            f"<b>🔍 Triage</b> · threat_level={triage.get('threat_level', '-')} · "
            f"detection={triage.get('detection_ratio', '-')}",
            styles["body"],
        ))
        story.append(Paragraph(triage.get("chat_message") or triage.get("notes", ""), styles["body"]))
        story.append(Spacer(1, 4))

    if malware.get("malware_family") or malware.get("chat_message"):
        story.append(Paragraph(
            f"<b>👾 Malware</b> · family={malware.get('malware_family') or '-'}",
            styles["body"],
        ))
        story.append(Paragraph(malware.get("chat_message") or malware.get("notes", ""), styles["body"]))
        story.append(Spacer(1, 4))

    if infra.get("chat_message"):
        story.append(Paragraph(
            f"<b>🌍 Infrastructure</b> · cluster={infra.get('campaign_cluster_id') or '-'} · "
            f"typosquats={len(infra.get('typosquat_domains') or [])}",
            styles["body"],
        ))
        story.append(Paragraph(infra.get("chat_message"), styles["body"]))
        story.append(Spacer(1, 4))

    if campaign.get("chat_message"):
        story.append(Paragraph(
            f"<b>📈 Campaign</b> · group={campaign.get('threat_group_hypothesis') or '-'}",
            styles["body"],
        ))
        story.append(Paragraph(campaign.get("chat_message"), styles["body"]))
        story.append(Spacer(1, 4))

    # ---- Executive Summary ----
    summary = deliverables.get("executive_summary") or campaign.get("executive_summary")
    if summary:
        story.append(Paragraph("📈 Executive Summary", styles["h2"]))
        story.append(Paragraph(summary, styles["body"]))

    # ---- 방화벽 규칙 ----
    fw_rules = deliverables.get("firewall_rules") or campaign.get("firewall_rules") or []
    if fw_rules:
        story.append(Paragraph(f"🛡️ 방화벽 차단 규칙 ({len(fw_rules)})", styles["h2"]))
        for r in fw_rules:
            story.append(Paragraph(r, styles["mono"]))

    # ---- 헌팅 가설 ----
    hunts = deliverables.get("hunt_hypotheses") or campaign.get("hunt_hypotheses") or []
    if hunts:
        story.append(Paragraph(f"🔍 헌팅 가설 ({len(hunts)})", styles["h2"]))
        for h in hunts:
            story.append(Paragraph(
                f"#{h.get('hypothesis_id', '?')} · {h.get('platform', '-')} · {h.get('timeline', '-')}",
                styles["body"],
            ))
            story.append(Paragraph(h.get("query", ""), styles["mono"]))
            story.append(Paragraph(
                f"Success criteria: {h.get('criteria', '-')}", styles["body"],
            ))
            story.append(Spacer(1, 2))

    # ---- Audit Ledger (footer) ----
    if ledger:
        story.append(Paragraph("📋 Audit Ledger", styles["h2"]))
        ledger_text = "  ·  ".join(
            f"{e.get('node')}({e.get('elapsed_ms', '?')}ms)" for e in ledger
        )
        story.append(Paragraph(ledger_text, styles["mono"]))

    doc.build(story)
    return buf.getvalue()
