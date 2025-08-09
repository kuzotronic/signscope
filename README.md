# signscope — “Human-grade EIP-712 explainability before you sign.”

**signscope** is a zero-RPC CLI that ingests **EIP-712 typed data** (what wallets
ask you to sign), prints a clean summary, flags risky patterns, and emits a
**stable fingerprint** so teams can review exactly the same payload in CI/PRs.

It recognizes **Permit (EIP-2612)**, **Permit2** (PermitSingle/Batch), and any
generic EIP-712 message. All offline, all deterministic.

## Why this matters

- Hex walls and raw JSON are easy to miss. A single *infinite allowance* or
  *deadline=0* can slip into a governance PR or backend change.
- **signscope** gives you a plain-English diff and a stable fingerprint for human
  review — before production wallets ever see the payload.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
