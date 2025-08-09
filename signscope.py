#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
signscope — human-grade explainability & lint for EIP-712 typed data (offline).

Commands
  analyze     Analyze a JSON file/string/stdin with EIP-712 typed data
  pretty      Human-readable summary to stdout
  fingerprint Stable keccak of a canonicalized JSON (for approvals/CI)
  svg-badge   Tiny badge with the fingerprint and risk tier

Notes
- This tool does NOT compute the on-chain EIP-712 digest; instead it computes
  a stable keccak256 over a normalized JSON view for reproducible review.
- No network calls, no ABI decoding required.

Examples
  $ python signscope.py analyze permit.json --pretty --json report.json --svg badge.svg
  $ cat typed.json | python signscope.py analyze - --pretty
"""

import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import click
from eth_utils import keccak, to_checksum_address, is_hex

UINT256_MAX = (1 << 256) - 1

# ----------------------------- Utilities -----------------------------

def _deep_sort(obj: Any) -> Any:
    """Recursively sort maps by key and lists by value for stable canonicalization."""
    if isinstance(obj, dict):
        return {k: _deep_sort(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_deep_sort(x) for x in obj]
    return obj

def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace ambiguity."""
    return json.dumps(_deep_sort(obj), separators=(",", ":"), ensure_ascii=False)

def _keccak_hex(data: bytes) -> str:
    return "0x" + keccak(data).hex()

def _short(addr: str) -> str:
    return addr[:6] + "…" + addr[-4:] if isinstance(addr, str) and len(addr) > 12 else str(addr)

def _as_int(x: Any) -> Optional[int]:
    try:
        if isinstance(x, str) and x.startswith("0x") and is_hex(x):
            return int(x, 16)
        return int(x)
    except Exception:
        return None

def _looks_address(s: str) -> bool:
    return isinstance(s, str) and s.lower().startswith("0x") and len(s) == 42

def _maybe_checksum(s: str) -> Optional[str]:
    try:
        return to_checksum_address(s) if _looks_address(s) else None
    except Exception:
        return None

# ----------------------------- Data types -----------------------------

@dataclass
class Finding:
    level: str   # LOW / MEDIUM / HIGH
    reason: str
    context: Dict[str, Any]

@dataclass
class Summary:
    kind: str                  # 'permit', 'permit2', 'generic'
    primaryType: str
    domain: Dict[str, Any]
    highlights: Dict[str, Any] # extracted key facts (spender, owner, value, deadline, etc.)

@dataclass
class Report:
    fingerprint: str
    risk_score: int
    risk_label: str
    summary: Summary
    findings: List[Finding]

# ----------------------------- Recognizers -----------------------------

def _is_permit(primary: str, msg: Dict[str, Any]) -> bool:
    return "permit" in primary.lower() and {"owner","spender","value","deadline"}.issubset(msg.keys())

def _is_permit2(primary: str, types: Dict[str, Any], msg: Dict[str, Any]) -> bool:
    # Rough: look for PermitSingle or PermitBatch shape
    p = primary.lower()
    if "permitsingle" in p or "permitbatch" in p:
        return True
    # Or a struct named PermitDetails with fields
    tnames = " ".join(types.keys()).lower() if isinstance(types, dict) else ""
    return "permitdetails" in tnames or "permitbatch" in tnames

# ----------------------------- Extractors -----------------------------

def _extract_permit(msg: Dict[str, Any]) -> Dict[str, Any]:
    owner = msg.get("owner")
    spender = msg.get("spender")
    value = _as_int(msg.get("value"))
    deadline = _as_int(msg.get("deadline"))
    nonce = _as_int(msg.get("nonce"))
    return {"owner": owner, "spender": spender, "value": value, "deadline": deadline, "nonce": nonce}

def _extract_permit2(msg: Dict[str, Any]) -> Dict[str, Any]:
    # Try common fields across PermitSingle
    d = msg.get("details", {})
    if isinstance(d, dict):
        token = d.get("token")
        amount = _as_int(d.get("amount"))
        expiration = _as_int(d.get("expiration"))
        nonce = _as_int(d.get("nonce"))
        spender = msg.get("spender")
        sig_deadline = _as_int(msg.get("sigDeadline") or msg.get("deadline"))
        return {"token": token, "spender": spender, "amount": amount, "expiration": expiration, "nonce": nonce, "sigDeadline": sig_deadline}
    # Fallback
    return {"_raw": msg}

# ----------------------------- Risk logic -----------------------------

def _risk_findings(primary: str, domain: Dict[str, Any], msg: Dict[str, Any], kind: str) -> List[Finding]:
    fs: List[Finding] = []

    # Domain checks
    chainId = _as_int(domain.get("chainId"))
    verifying = domain.get("verifyingContract")
    version = domain.get("version")

    if chainId is not None and chainId not in (1, 10, 56, 137, 8453, 42161, 43114, 11155111):
        fs.append(Finding("LOW", "Uncommon chainId", {"chainId": chainId}))
    if verifying and _looks_address(verifying):
        checksummed = _maybe_checksum(verifying)
        if checksummed and checksummed != verifying:
            fs.append(Finding("MEDIUM", "Domain.verifyContract not checksummed", {"verifyingContract": verifying}))
    elif verifying:
        fs.append(Finding("MEDIUM", "Domain.verifyContract not an address", {"verifyingContract": verifying}))

    # Message-level checks
    if kind == "permit":
        ext = _extract_permit(msg)
        if ext["value"] == UINT256_MAX:
            fs.append(Finding("HIGH", "Infinite ERC-20 allowance (value = 2^256-1)", {"spender": ext["spender"]}))
        if ext["deadline"] is None:
            fs.append(Finding("MEDIUM", "Missing deadline in Permit", {}))
        elif ext["deadline"] == 0:
            fs.append(Finding("HIGH", "Permit with deadline = 0 (no expiry)", {}))
        elif ext["deadline"] and ext["deadline"] > 2**31:
            fs.append(Finding("LOW", "Very far future deadline (epoch seconds?)", {"deadline": ext["deadline"]}))
        if ext["owner"] and _looks_address(ext["owner"]):
            chk = _maybe_checksum(ext["owner"])
            if chk and chk != ext["owner"]:
                fs.append(Finding("LOW", "Owner not checksummed", {"owner": ext["owner"]}))
        if ext["spender"] and _looks_address(ext["spender"]):
            chk = _maybe_checksum(ext["spender"])
            if chk and chk != ext["spender"]:
                fs.append(Finding("LOW", "Spender not checksummed", {"spender": ext["spender"]}))

    elif kind == "permit2":
        ext = _extract_permit2(msg)
        if ext.get("amount") == UINT256_MAX:
            fs.append(Finding("HIGH", "Permit2 infinite amount", {"spender": ext.get("spender")}))
        expiration = ext.get("expiration")
        if expiration is not None and expiration == 0:
            fs.append(Finding("HIGH", "Permit2 expiration = 0 (no expiry)", {}))
        sigdl = ext.get("sigDeadline")
        if sigdl is not None and sigdl == 0:
            fs.append(Finding("MEDIUM", "Permit2 sigDeadline = 0", {}))

    else:
        # Generic sanity
        # If any obvious allowance fields exist, try to catch extremes
        value = _as_int(msg.get("value"))
        if value == UINT256_MAX:
            fs.append(Finding("HIGH", "Value looks like infinite limit", {}))

    # Duplicated or unexpected fields?
    # (JSON doesn't preserve duplicates; leave this as a placeholder for future streaming parser.)

    return fs

def _risk_score(fs: List[Finding]) -> Tuple[int, str]:
    score = 0
    for f in fs:
        score += 35 if f.level == "HIGH" else 15 if f.level == "MEDIUM" else 5
    score = min(100, score)
    label = "HIGH" if score >= 70 else "MEDIUM" if score >= 30 else "LOW"
    return score, label

# ----------------------------- Core analysis -----------------------------

def _load_typed(input_arg: str) -> Dict[str, Any]:
    """
    Accept:
      - '-' for stdin
      - path to JSON file
      - inline JSON string
    """
    if input_arg == "-":
        text = sys.stdin.read()
    elif os.path.isfile(input_arg):
        with open(input_arg, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = input_arg
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON: {e}")
    return obj

def analyze_typed(typed: Dict[str, Any]) -> Report:
    # Normalize shape: some libs wrap as {domain, message, types, primaryType}
    domain = typed.get("domain", {})
    message = typed.get("message", {})
    primary = typed.get("primaryType") or ""
    types = typed.get("types", {})

    # Determine kind
    if _is_permit(primary, message):
        kind = "permit"
        highlights = _extract_permit(message)
    elif _is_permit2(primary, types, message):
        kind = "permit2"
        highlights = _extract_permit2(message)
    else:
        kind = "generic"
        # Pull out obvious addresses & numbers for quick glance
        highlights = {}
        for k, v in message.items():
            if _looks_address(str(v)):
                highlights[k] = v
            else:
                iv = _as_int(v)
                if iv is not None:
                    highlights[k] = iv

    # Findings & risk
    findings = _risk_findings(primary, domain, message, kind)
    risk, label = _risk_score(findings)

    # Stable fingerprint over canonicalized {domain, message, primaryType, types}
    mat = {"domain": domain, "message": message, "primaryType": primary, "types": types}
    fp = _keccak_hex(_canonical_json(mat).encode("utf-8"))

    summary = Summary(kind=kind, primaryType=primary, domain=domain, highlights=highlights)
    return Report(fingerprint=fp, risk_score=risk, risk_label=label, summary=summary, findings=findings)

# ----------------------------- CLI -----------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """signscope — human-grade EIP-712 explainability & lint (offline)."""
    pass

@cli.command("analyze")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write an SVG badge.")
@click.option("--pretty", is_flag=True, help="Print a human-readable summary.")
def analyze_cmd(input_arg, json_out, svg_out, pretty):
    typed = _load_typed(input_arg)
    rep = analyze_typed(typed)

    if pretty:
        pt = rep.summary.primaryType or "<unknown>"
        click.echo(f"signscope — {rep.summary.kind}  primaryType={pt}")
        click.echo(f"fingerprint: {rep.fingerprint}  risk {rep.risk_score}/100 ({rep.risk_label})")
        # Domain quick view
        dom = rep.summary.domain
        vrf = dom.get("verifyingContract")
        chainId = dom.get("chainId")
        ver = dom.get("version")
        click.echo(f"domain: verifyingContract={_short(str(vrf))}  chainId={chainId}  version={ver}")
        # Highlights
        if rep.summary.highlights:
            click.echo("highlights:")
            for k, v in rep.summary.highlights.items():
                click.echo(f"  - {k}: {v}")
        # Findings
        if rep.findings:
            click.echo("findings:")
            for f in rep.findings:
                click.echo(f"  - {f.level}: {f.reason} {f.context}")
        else:
            click.echo("findings: (none)")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({
                "fingerprint": rep.fingerprint,
                "risk_score": rep.risk_score,
                "risk_label": rep.risk_label,
                "summary": {
                    "kind": rep.summary.kind,
                    "primaryType": rep.summary.primaryType,
                    "domain": rep.summary.domain,
                    "highlights": rep.summary.highlights
                },
                "findings": [asdict(x) for x in rep.findings]
            }, f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if svg_out:
        color = "#3fb950" if rep.risk_score < 30 else "#d29922" if rep.risk_score < 70 else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="560" height="48" role="img" aria-label="EIP-712 risk">
  <rect width="560" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    signscope: {rep.summary.kind}  risk {rep.risk_score}/100 ({rep.risk_label})  {rep.fingerprint[:18]}…
  </text>
  <circle cx="535" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    # Default: output JSON to stdout if no flags
    if not (pretty or json_out or svg_out):
        click.echo(json.dumps({
            "fingerprint": rep.fingerprint,
            "risk_score": rep.risk_score,
            "risk_label": rep.risk_label,
            "summary": {
                "kind": rep.summary.kind,
                "primaryType": rep.summary.primaryType,
                "domain": rep.summary.domain,
                "highlights": rep.summary.highlights
            },
            "findings": [asdict(x) for x in rep.findings]
        }, indent=2))

@cli.command("pretty")
@click.argument("input_arg", type=str)
def pretty_cmd(input_arg):
    """Shortcut for `analyze --pretty`."""
    typed = _load_typed(input_arg)
    rep = analyze_typed(typed)
    pt = rep.summary.primaryType or "<unknown>"
    click.echo(f"signscope — {rep.summary.kind}  primaryType={pt}")
    click.echo(f"fingerprint: {rep.fingerprint}  risk {rep.risk_score}/100 ({rep.risk_label})")
    dom = rep.summary.domain
    click.echo(f"domain: verifyingContract={_short(str(dom.get('verifyingContract')))}  chainId={dom.get('chainId')}  version={dom.get('version')}")
    if rep.summary.highlights:
        click.echo("highlights:")
        for k, v in rep.summary.highlights.items():
            click.echo(f"  - {k}: {v}")
    if rep.findings:
        click.echo("findings:")
        for f in rep.findings:
            click.echo(f"  - {f.level}: {f.reason} {f.context}")
    else:
        click.echo("findings: (none)")

@cli.command("fingerprint")
@click.argument("input_arg", type=str)
def fp_cmd(input_arg):
    """Print only the canonical fingerprint of the typed data."""
    typed = _load_typed(input_arg)
    mat = {"domain": typed.get("domain", {}), "message": typed.get("message", {}), "primaryType": typed.get("primaryType"), "types": typed.get("types", {})}
    fp = _keccak_hex(_canonical_json(mat).encode("utf-8"))
    click.echo(fp)

@cli.command("svg-badge")
@click.argument("input_arg", type=str)
@click.option("--out", type=click.Path(writable=True), default="signscope-badge.svg", show_default=True)
def badge_cmd(input_arg, out):
    """Write a small SVG badge with fingerprint and generic risk label."""
    typed = _load_typed(input_arg)
    rep = analyze_typed(typed)
    color = "#3fb950" if rep.risk_score < 30 else "#d29922" if rep.risk_score < 70 else "#f85149"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="560" height="48" role="img" aria-label="EIP-712 risk">
  <rect width="560" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    signscope: {rep.summary.kind}  risk {rep.risk_score}/100 ({rep.risk_label})  {rep.fingerprint[:18]}…
  </text>
  <circle cx="535" cy="24" r="6" fill="{color}"/>
</svg>"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg)
    click.echo(f"Wrote SVG badge: {out}")

if __name__ == "__main__":
    cli()
