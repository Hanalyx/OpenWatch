"""PDF output formatter for compliance results.

Produces formatted PDF reports suitable for:
- Executive summaries and management review
- Audit documentation and compliance evidence
- Printing and offline review
- Formal reporting requirements

Report Structure:
    1. Title and timestamp
    2. Summary table (hosts, pass/fail/skip counts)
    3. Per-host sections with:
       - Platform information
       - Color-coded results table (PASS=green, FAIL=red, SKIP=grey)

Requirements:
    This formatter requires the reportlab library:
        pip install reportlab

    If reportlab is not installed, format_pdf() raises ImportError
    with installation instructions.

Example:
-------
    >>> from runner.output import RunResult, format_pdf
    >>> result = RunResult(command="check")
    >>> format_pdf(result, "compliance_report.pdf")
    >>> # PDF file is written to disk

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.output import RunResult


# ── Optional dependency handling ───────────────────────────────────────────
#
# reportlab is optional - we detect its presence at import time and provide
# a clear error message if it's missing when format_pdf() is called.

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ── Status colors ──────────────────────────────────────────────────────────
#
# Color coding for result status cells in the PDF table.
# Using light variants for readability with black text.

STATUS_COLORS = {
    "PASS": "lightgreen",  # colors.lightgreen when reportlab loaded
    "FAIL": "lightcoral",
    "SKIP": "lightgrey",
}


def format_pdf(run_result: RunResult, filepath: str) -> None:
    """Format compliance results as a PDF report.

    Unlike text formatters, this writes directly to a file since PDF is
    a binary format. The report includes a summary section and per-host
    detail tables with color-coded status indicators.

    Args:
        run_result: Aggregated results from a compliance run.
        filepath: Path to write the PDF file.

    Raises:
        ImportError: If reportlab library is not installed.

    Report Sections:
        1. Header: "Aegis Compliance Report" title
        2. Metadata: Timestamp and command type
        3. Summary Table: Aggregate counts (hosts, pass, fail, skip, fixed)
        4. Per-Host Details: For each host:
           - Hostname heading
           - Platform info (if detected)
           - Results table with columns: Rule ID, Status, Severity, Title
           - Status cells are color-coded (green/red/grey)

    Note:
        Long rule titles are truncated to 50 characters with "..." suffix
        to maintain table formatting.

    Example:
    -------
        >>> from runner.output import RunResult, format_pdf
        >>> result = RunResult(command="check")
        >>> # ... populate result ...
        >>> format_pdf(result, "report.pdf")

    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("PDF output requires the reportlab library. Install with: pip install reportlab")

    doc = _create_document(filepath)
    styles = _create_styles()
    elements = []

    # Title and metadata
    elements.extend(_build_header(run_result, styles))

    # Summary table
    elements.extend(_build_summary_table(run_result))

    # Per-host results
    for host in run_result.hosts:
        elements.extend(_build_host_section(host, run_result.command, styles))

    doc.build(elements)


def _create_document(filepath: str):
    """Create a SimpleDocTemplate with standard margins.

    Args:
        filepath: Path for the output PDF.

    Returns:
        Configured SimpleDocTemplate instance.

    """
    return SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )


def _create_styles() -> dict:
    """Create paragraph styles for the report.

    Returns:
        Dict with 'title', 'heading', and 'normal' style objects.

    """
    base_styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title",
            parent=base_styles["Heading1"],
            fontSize=18,
            spaceAfter=12,
        ),
        "heading": ParagraphStyle(
            "Heading",
            parent=base_styles["Heading2"],
            fontSize=14,
            spaceAfter=6,
        ),
        "normal": base_styles["Normal"],
    }


def _build_header(run_result: RunResult, styles: dict) -> list:
    """Build title and metadata elements.

    Args:
        run_result: The run results for timestamp/command info.
        styles: Dict of paragraph styles.

    Returns:
        List of Paragraph and Spacer elements.

    """
    return [
        Paragraph("Aegis Compliance Report", styles["title"]),
        Spacer(1, 0.2 * inch),
        Paragraph(f"Timestamp: {run_result.timestamp.isoformat()}", styles["normal"]),
        Paragraph(f"Command: {run_result.command}", styles["normal"]),
        Spacer(1, 0.1 * inch),
    ]


def _build_summary_table(run_result: RunResult) -> list:
    """Build the summary statistics table.

    Args:
        run_result: The run results for aggregate counts.

    Returns:
        List containing the Table and a Spacer.

    """
    data = [
        ["Metric", "Value"],
        ["Hosts", str(run_result.host_count)],
        [
            "Total Checks",
            str(run_result.total_pass + run_result.total_fail + run_result.total_skip),
        ],
        ["Passed", str(run_result.total_pass)],
        ["Failed", str(run_result.total_fail)],
        ["Skipped", str(run_result.total_skip)],
    ]

    if run_result.command == "remediate":
        data.append(["Fixed", str(run_result.total_fixed)])

    table = Table(data, colWidths=[2 * inch, 1.5 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )

    return [table, Spacer(1, 0.3 * inch)]


def _build_host_section(host, command: str, styles: dict) -> list:
    """Build the section for a single host.

    Args:
        host: HostResult object.
        command: "check" or "remediate".
        styles: Dict of paragraph styles.

    Returns:
        List of elements for this host's section.

    """
    elements = [Paragraph(f"Host: {host.hostname}", styles["heading"])]

    if host.error:
        elements.append(Paragraph(f"Error: {host.error}", styles["normal"]))
        elements.append(Spacer(1, 0.2 * inch))
        return elements

    if host.platform_family:
        elements.append(
            Paragraph(
                f"Platform: {host.platform_family} {host.platform_version or ''}",
                styles["normal"],
            )
        )

    if host.results:
        elements.append(_build_results_table(host.results))

    elements.append(Spacer(1, 0.3 * inch))
    return elements


def _build_results_table(results: list):
    """Build the results table for a host.

    Args:
        results: List of RuleResult objects.

    Returns:
        Configured Table with color-coded status cells.

    """
    # Check if any results have framework_section (i.e., --framework was used)
    has_framework = any(getattr(r, "framework_section", None) for r in results)

    if has_framework:
        data = [["Section", "Rule ID", "Status", "Severity", "Title"]]
        for result in results:
            status = _get_status_label(result)
            title = _truncate_title(result.title, max_length=45)
            section = getattr(result, "framework_section", None) or ""
            data.append([section, result.rule_id, status, result.severity or "", title])
        table = Table(
            data,
            colWidths=[0.7 * inch, 2.2 * inch, 0.6 * inch, 0.7 * inch, 3.2 * inch],
        )
    else:
        data = [["Rule ID", "Status", "Severity", "Title"]]
        for result in results:
            status = _get_status_label(result)
            title = _truncate_title(result.title, max_length=50)
            data.append([result.rule_id, status, result.severity or "", title])
        table = Table(
            data,
            colWidths=[2.5 * inch, 0.6 * inch, 0.8 * inch, 3.5 * inch],
        )

    style = _build_table_style(data, has_framework=has_framework)
    table.setStyle(TableStyle(style))

    return table


def _get_status_label(result) -> str:
    """Get the status label for a result.

    Args:
        result: RuleResult object.

    Returns:
        "PASS", "FAIL", or "SKIP".

    """
    if result.skipped:
        return "SKIP"
    elif result.passed:
        return "PASS"
    else:
        return "FAIL"


def _truncate_title(title: str, max_length: int) -> str:
    """Truncate a title to fit in the table column.

    Args:
        title: The full title string.
        max_length: Maximum length before truncation.

    Returns:
        Original title or truncated with "..." suffix.

    """
    if len(title) > max_length:
        return title[:max_length] + "..."
    return title


def _build_table_style(data: list, *, has_framework: bool = False) -> list:
    """Build table style with color-coded status cells.

    Args:
        data: Table data including header row.
        has_framework: Whether the Section column is present.

    Returns:
        List of TableStyle tuples.

    """
    # Status column is at index 2 if has_framework (Section, Rule ID, Status),
    # otherwise at index 1 (Rule ID, Status)
    status_col = 2 if has_framework else 1

    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (status_col, 0), (status_col, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
    ]

    # Color-code status cells based on value
    for i, row in enumerate(data[1:], start=1):
        status = row[status_col]
        if status == "PASS":
            style.append(("BACKGROUND", (status_col, i), (status_col, i), colors.lightgreen))
        elif status == "FAIL":
            style.append(("BACKGROUND", (status_col, i), (status_col, i), colors.lightcoral))
        else:  # SKIP
            style.append(("BACKGROUND", (status_col, i), (status_col, i), colors.lightgrey))

    return style
