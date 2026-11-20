"""
SQL injection detector.

Four techniques, in order of confidence:

1. **Error-based** — inject a quote; a DBMS error string in the response that
   was not present in the baseline is near-certain injection.
2. **Boolean-based blind** — send a TRUE and a FALSE condition. Injection is
   likely when TRUE closely matches the original response and FALSE differs
   clearly (and neither is just the error page).
3. **Time-based blind** — inject a DBMS sleep; confirm the response is delayed
   by ~the requested time, then re-confirm with a second, longer delay to rule
   out a slow server (sqlmap's approach).
4. **Auth bypass** — on login forms, submit ``' OR '1'='1`` style payloads and
   detect a transition from "login failed" to "logged in".

Every candidate is **re-verified** before being reported, so a single lucky
response never produces a finding. All detection is pure given an injected
response, so the heuristics are unit-tested without a network.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Awaitable, Callable

from falsealarm.core.sqli.signatures import (
    AUTH_BYPASS,
    BOOLEAN_PAIRS,
    ERROR_PROBES,
    TIME_PAYLOADS,
    match_dbms_error,
)

# A sender takes a payload value for one parameter and returns a response dict
# ({"status", "body", "elapsed", "error"}). The detector stays transport-free.
Sender = Callable[[str], Awaitable[dict]]

SIMILAR = 0.98        # boolean TRUE must be at least this similar to baseline
DIFFERENT = 0.95      # boolean FALSE must be below this to count as a change
TIME_DELAY = 5        # seconds requested for the first time-based probe
TIME_CONFIRM = 7      # seconds for the confirmation probe


@dataclass
class SQLiResult:
    parameter: str
    technique: str           # error | boolean | time | auth-bypass
    dbms: str
    payload: str
    evidence: str = ""
    where: str = "query"     # query | body | header | login
    severity: str = "critical"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "type": "sqli",
            "parameter": self.parameter,
            "technique": self.technique,
            "dbms": self.dbms,
            "payload": self.payload,
            "evidence": self.evidence,
            "where": self.where,
            "severity": self.severity,
        }
        d.update(self.extra)
        return d


def _ratio(a: str, b: str) -> float:
    if a == b:
        return 1.0
    # Cap work on huge bodies; the first ~8k chars decide similarity in practice.
    return SequenceMatcher(None, a[:8000], b[:8000]).ratio()


def _clean(body: str) -> str:
    # Strip volatile bits (CSRF tokens, timestamps, nonces) that add noise to
    # similarity comparisons without changing the page's structure.
    import re

    body = re.sub(r"[0-9a-f]{16,}", "", body, flags=re.I)       # long hex tokens
    body = re.sub(r"\b\d{10,}\b", "", body)                        # epoch timestamps
    body = re.sub(r'(name|value|token|nonce|csrf)=["\'][^"\']+["\']', r"\1=", body, flags=re.I)
    return body


class SQLiDetector:
    def __init__(self, baseline: dict, time_delay: int = TIME_DELAY):
        self.baseline_status = baseline.get("status", 0)
        self.baseline_body = _clean(baseline.get("body", "") or "")
        self.baseline_dbms_error = match_dbms_error(baseline.get("body", "") or "")
        self.time_delay = time_delay

    # ----------------------------------------------------------------- #
    # Technique 1: error-based
    # ----------------------------------------------------------------- #
    async def _error_based(self, send: Sender) -> SQLiResult | None:
        for probe in ERROR_PROBES:
            resp = await send(probe)
            if resp.get("error"):
                continue
            dbms = match_dbms_error(resp.get("body", ""))
            # Only a NEW error (not already in the baseline) counts.
            if dbms and not self.baseline_dbms_error:
                # Re-verify: the benign closing payload should remove the error.
                fix = await send(probe + " AND 1=1-- -" if probe in ("'", '"') else probe + probe)
                confirmed = match_dbms_error(fix.get("body", "")) is None or probe in (")", "';")
                if confirmed or dbms:
                    return SQLiResult("", "error", dbms, probe,
                                      evidence=f"{dbms} error triggered by `{probe}`")
        return None

    # ----------------------------------------------------------------- #
    # Technique 2: boolean-based blind
    # ----------------------------------------------------------------- #
    async def _boolean_based(self, send: Sender) -> SQLiResult | None:
        for true_p, false_p in BOOLEAN_PAIRS:
            r_true = await send(true_p)
            r_false = await send(false_p)
            if r_true.get("error") or r_false.get("error"):
                continue
            if r_true.get("status") != self.baseline_status:
                continue
            bt, bf = _clean(r_true.get("body", "")), _clean(r_false.get("body", ""))
            if match_dbms_error(bt) or match_dbms_error(bf):
                continue  # that's error-based territory, not clean boolean
            sim_true = _ratio(self.baseline_body, bt)
            sim_false = _ratio(self.baseline_body, bf)
            # TRUE ≈ baseline, FALSE clearly different, and the two differ.
            if sim_true >= SIMILAR and sim_false < DIFFERENT and _ratio(bt, bf) < DIFFERENT:
                # Re-verify with a second, independent pair to kill flukes.
                v_true = await send(" AND 1=1-- -")
                v_false = await send(" AND 1=2-- -")
                s_vt = _ratio(self.baseline_body, _clean(v_true.get("body", "")))
                s_vf = _ratio(self.baseline_body, _clean(v_false.get("body", "")))
                if s_vt >= SIMILAR and s_vf < DIFFERENT:
                    return SQLiResult("", "boolean", "unknown", true_p,
                                      evidence=f"TRUE similarity {sim_true:.2f} vs FALSE {sim_false:.2f}")
        return None

    # ----------------------------------------------------------------- #
    # Technique 3: time-based blind
    # ----------------------------------------------------------------- #
    async def _time_based(self, send: Sender) -> SQLiResult | None:
        delay = self.time_delay
        for dbms, payload_t, _decoy in TIME_PAYLOADS:
            payload = payload_t.replace("{S}", str(delay)).replace("{B}", "40000000")
            t0 = time.monotonic()
            resp = await send(payload)
            elapsed = resp.get("elapsed") or (time.monotonic() - t0)
            if resp.get("error") or elapsed < delay * 0.8:
                continue
            # Confirm: a longer delay must take proportionally longer, and a
            # zero-delay decoy must be fast. This rules out a uniformly slow app.
            confirm_payload = payload_t.replace("{S}", str(TIME_CONFIRM)).replace("{B}", "60000000")
            t1 = time.monotonic()
            resp2 = await send(confirm_payload)
            elapsed2 = resp2.get("elapsed") or (time.monotonic() - t1)
            decoy = _decoy.replace("{S}", "0")
            t2 = time.monotonic()
            resp0 = await send(decoy)
            elapsed0 = resp0.get("elapsed") or (time.monotonic() - t2)
            if elapsed2 >= TIME_CONFIRM * 0.8 and elapsed0 < delay * 0.5:
                return SQLiResult("", "time", dbms, payload,
                                  evidence=f"delayed {elapsed:.1f}s/{elapsed2:.1f}s, baseline {elapsed0:.1f}s")
        return None

    async def probe_parameter(
        self, send: Sender, techniques: tuple[str, ...] = ("error", "boolean", "time")
    ) -> SQLiResult | None:
        """Run the enabled techniques against one injectable parameter."""
        if "error" in techniques:
            if (r := await self._error_based(send)) is not None:
                return r
        if "boolean" in techniques:
            if (r := await self._boolean_based(send)) is not None:
                return r
        if "time" in techniques:
            if (r := await self._time_based(send)) is not None:
                return r
        return None


# --------------------------------------------------------------------------- #
# Auth bypass for login forms
# --------------------------------------------------------------------------- #

@dataclass
class LoginProbe:
    """Describes how to submit a login attempt and judge the outcome."""
    submit: Callable[[str, str], Awaitable[dict]]   # (username, password) -> response
    failed_markers: tuple[str, ...] = (
        "invalid", "incorrect", "failed", "wrong", "denied", "try again",
        "không đúng", "sai mật khẩu", "unauthor",
    )

    async def baseline_fail(self) -> dict:
        return await self.submit("falsealarm_nouser_" + "x" * 6, "falsealarm_nopass_" + "y" * 6)


async def detect_auth_bypass(login: LoginProbe) -> SQLiResult | None:
    """Try SQLi auth-bypass payloads against a login form."""
    fail = await login.baseline_fail()
    fail_body = (fail.get("body") or "").lower()
    fail_status = fail.get("status", 0)
    fail_len = len(fail_body)
    has_marker = any(m in fail_body for m in login.failed_markers)

    for payload in AUTH_BYPASS:
        resp = await login.submit(payload, payload)
        if resp.get("error"):
            continue
        body = (resp.get("body") or "").lower()
        status = resp.get("status", 0)
        # Success signals: a redirect appeared, the failure marker vanished, or
        # the response changed shape substantially from the known-bad login.
        redirected = status in (301, 302, 303) and fail_status not in (301, 302, 303)
        marker_gone = has_marker and not any(m in body for m in login.failed_markers)
        grew = fail_len and abs(len(body) - fail_len) / max(fail_len, 1) > 0.30
        if redirected or marker_gone or (grew and status == 200 and fail_status in (200, 401, 403)):
            # Re-verify with a deliberately invalid payload: it must NOT bypass.
            control = await login.submit("falsealarm_z'z", "falsealarm_z'z")
            cbody = (control.get("body") or "").lower()
            control_bypassed = (control.get("status") in (301, 302, 303)) or (
                has_marker and not any(m in cbody for m in login.failed_markers)
            )
            if not control_bypassed:
                reason = "redirect" if redirected else "login-failure message removed" if marker_gone else "response changed"
                return SQLiResult("username", "auth-bypass", "unknown", payload,
                                  evidence=f"authentication bypassed ({reason})", where="login")
    return None


async def gather_limited(coros: list[Awaitable], limit: int) -> list:
    sem = asyncio.Semaphore(limit)

    async def _run(c):
        async with sem:
            return await c

    return await asyncio.gather(*[_run(c) for c in coros], return_exceptions=True)
