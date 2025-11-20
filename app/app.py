from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Tuple
import re

app = FastAPI(
    title="Rule 2431747 — Obsolete FI/CO Tables Scanner",
    version="2.0",
)

# ---------------------------------------------------------------------------
# Table mapping & config
# ---------------------------------------------------------------------------
TABLE_MAPPING = {
    "BSIS": {"source": "ACDOCA", "view": True},
    "BSEG": {"source": "ACDOCA", "view": True},
    "BSAS": {"source": "ACDOCA", "view": True},
    "BSIK": {"source": "ACDOCA", "view": True},
    "BSAK": {"source": "ACDOCA", "view": True},
    "BSID": {"source": "ACDOCA", "view": True},
    "BSAD": {"source": "ACDOCA", "view": True},
    "GLT0": {"source": "ACDOCA", "view": True},
    "COEP": {"source": "ACDOCA", "view": True},
    "COSP": {"source": "ACDOCA", "view": True},
    "COSS": {"source": "ACDOCA", "view": True},
    "MLIT": {"source": "ACDOCA", "view": True},
    "ANEP": {"source": "ACDOCA", "view": True},
    "ANLP": {"source": "ACDOCA", "view": True},
}
NO_VIEW_TABLES = {"FAGLFLEXA", "FAGLFLEXT"}

OBSOLETE_TABLES = set(TABLE_MAPPING.keys()) | set(NO_VIEW_TABLES)

LITERAL_TABLES_RE = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in OBSOLETE_TABLES) + r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Models (reference style)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None      # ObsoleteTableSelect / ObsoleteTableUpdate / Join / Literal
    severity: Optional[str] = None         # always "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None          # full line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = None
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which that match occurs.
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


def get_replacement_table(table: str) -> str:
    t_up = (table or "").upper()
    if t_up in NO_VIEW_TABLES:
        return "ACDOCA"
    elif t_up in TABLE_MAPPING:
        return TABLE_MAPPING[t_up]["source"].split("/")[0]
    return t_up


def build_message_and_suggestion(table: str, context: str) -> Tuple[str, str]:
    """
    context: 'SELECT', 'UPDATE', 'DELETE', 'INSERT', 'MODIFY', 'JOIN', 'LITERAL'
    """
    t_up = (table or "").upper()
    rep = get_replacement_table(t_up)

    if context in ("UPDATE", "DELETE", "INSERT", "MODIFY"):
        msg = f"{context} on obsolete FI/CO table {t_up}."
        sug = (
            f"Avoid write operations on obsolete/compatibility tables like {t_up}. "
            f"Redesign to use {rep} (ACDOCA-based model) and adjusted logic per SAP Note 2431747."
        )
    elif context == "SELECT":
        msg = f"SELECT on obsolete FI/CO table {t_up}."
        sug = (
            f"Use {rep} (ACDOCA-based model or compatibility views) instead of {t_up} "
            f"and adapt joins/fields according to SAP Note 2431747."
        )
    elif context == "JOIN":
        msg = f"JOIN on obsolete FI/CO table {t_up}."
        sug = (
            f"Replace {t_up} in the JOIN with {rep} (ACDOCA-based model) and adjust the "
            f"selection/aggregation logic per SAP Note 2431747."
        )
    else:  # LITERAL
        msg = f"Obsolete FI/CO table {t_up} used as literal."
        sug = (
            f"Replace literal {t_up} with {rep} where applicable and ensure logic is "
            f"aligned with ACDOCA-based data model (SAP Note 2431747)."
        )

    return msg, sug


def make_finding(
    unit: Unit,
    src: str,
    base_start: int,
    match_start: int,
    match_end: int,
    issue_type: str,
    table: str,
    context: str,
) -> Finding:
    line_in_block = src[:match_start].count("\n") + 1
    snippet_line = get_line_snippet(src, match_start, match_end)
    snippet_line_count = snippet_line.count("\n") + 1

    starting_line_abs = base_start + line_in_block
    ending_line_abs = base_start + line_in_block + snippet_line_count

    msg, sug = build_message_and_suggestion(table, context)

    return Finding(
        prog_name=unit.pgm_name,
        incl_name=unit.inc_name,
        types=unit.type,
        blockname=unit.name,
        starting_line=starting_line_abs,
        ending_line=ending_line_abs,
        issues_type=issue_type,
        severity="error",
        message=msg,
        suggestion=sug,
        snippet=snippet_line.replace("\n", "\\n"),
    )


# ---------------------------------------------------------------------------
# Regexes for statements
# ---------------------------------------------------------------------------
SELECT_SIMPLE_RE = re.compile(
    r"""(?P<full>
            SELECT\s+(?:SINGLE\s+)?        
            (?P<fields>[\w\s,*]+)          
            \s+FROM\s+(?P<table>\w+)       
            (?P<middle>.*?)                
            (?:
                (?:INTO\s+TABLE\s+(?P<into_tab>[\w@()\->]+))
              | (?:INTO\s+(?P<into_wa>[\w@()\->]+))
            )
            (?P<tail>.*?)
        )\.""",
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

UPDATE_RE = re.compile(r"(UPDATE\s+(\w+)[\s\S]*?\.)", re.IGNORECASE)
DELETE_RE = re.compile(r"(DELETE\s+FROM\s+(\w+)[\s\S]*?\.)", re.IGNORECASE)
INSERT_RE = re.compile(r"(INSERT\s+(\w+)[\s\S]*?\.)", re.IGNORECASE)
MODIFY_RE = re.compile(r"(MODIFY\s+(\w+)[\s\S]*?\.)", re.IGNORECASE)

# SELECT ... FROM ... . (for JOIN scan)
SELECT_BLOCK_RE = re.compile(r"SELECT[\s\S]*?FROM\s+\w+[\s\S]*?\.", re.IGNORECASE)
JOIN_RE = re.compile(r"\bJOIN\s+(\w+)\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Core scanner (scan-only)
# ---------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    base_start = unit.start_line or 0

    findings: List[Finding] = []
    covered_spans: List[Tuple[int, int]] = []  # for dedup vs literal

    # 1) Simple single-table SELECT
    for m in SELECT_SIMPLE_RE.finditer(src):
        table = m.group("table")
        t_up = (table or "").upper()
        if t_up in OBSOLETE_TABLES:
            f = make_finding(
                unit=unit,
                src=src,
                base_start=base_start,
                match_start=m.start(),
                match_end=m.end(),
                issue_type="ObsoleteTableSelect",
                table=table,
                context="SELECT",
            )
            findings.append(f)
            covered_spans.append((m.start(), m.end()))

    # 2) UPDATE / DELETE / INSERT / MODIFY
    for stmt_type, pattern, issue_prefix in [
        ("UPDATE", UPDATE_RE, "ObsoleteTableUpdate"),
        ("DELETE", DELETE_RE, "ObsoleteTableDelete"),
        ("INSERT", INSERT_RE, "ObsoleteTableInsert"),
        ("MODIFY", MODIFY_RE, "ObsoleteTableModify"),
    ]:
        for m in pattern.finditer(src):
            stmt_text = m.group(1)
            table = m.group(2)
            t_up = (table or "").upper()
            if t_up in OBSOLETE_TABLES:
                f = make_finding(
                    unit=unit,
                    src=src,
                    base_start=base_start,
                    match_start=m.start(1),
                    match_end=m.end(1),
                    issue_type=issue_prefix,
                    table=table,
                    context=stmt_type,
                )
                findings.append(f)
                covered_spans.append((m.start(1), m.end(1)))

    # 3) JOIN on obsolete tables inside any SELECT block
    for select_match in SELECT_BLOCK_RE.finditer(src):
        block = select_match.group(0)
        block_start = select_match.start()
        for join in JOIN_RE.finditer(block):
            table = join.group(1)
            t_up = table.upper()
            if t_up in OBSOLETE_TABLES:
                start = block_start + join.start(1)
                end = block_start + join.end(1)
                f = make_finding(
                    unit=unit,
                    src=src,
                    base_start=base_start,
                    match_start=start,
                    match_end=end,
                    issue_type="ObsoleteTableJoin",
                    table=table,
                    context="JOIN",
                )
                findings.append(f)
                covered_spans.append((start, end))

    # 4) Literal usage anywhere
    for m in LITERAL_TABLES_RE.finditer(src):
        table = m.group(1)
        t_up = table.upper()
        start, end = m.start(), m.end()

        # Skip if already covered by a prior statement/join finding
        if any(start >= s and end <= e for (s, e) in covered_spans):
            continue

        f = make_finding(
            unit=unit,
            src=src,
            base_start=base_start,
            match_start=start,
            match_end=end,
            issue_type="ObsoleteTableLiteral",
            table=table,
            context="LITERAL",
        )
        findings.append(f)
        covered_spans.append((start, end))

    out_unit = Unit(**unit.model_dump())
    out_unit.findings = findings if findings else None
    return out_unit


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def remediate_array(units: List[Unit] = Body(...)):
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def remediate_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
def health():
    return {"ok": True, "rule": 2431747, "version": "2.0"}
