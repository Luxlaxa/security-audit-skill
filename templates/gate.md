# Pre-Deploy Security Gate Template

Use ONE of the three output formats below based on the audit results.

---

## Format 1: FAIL (any Critical findings present)

```
🔒 SECURITY GATE: FAIL ❌  (Grade: [GRADE], Score: [SCORE])

🚨 Critical ([COUNT]):
   - [FINDING_DESCRIPTION] ([DOMAIN])
   - [FINDING_DESCRIPTION] ([DOMAIN])

⚠️  High ([COUNT]):
   - [FINDING_DESCRIPTION] ([DOMAIN])

Action required: Fix all Critical findings before pushing.
```

[Omit the High section entirely if count is 0.]

---

## Format 2: PASS with warnings (High findings present, no Criticals)

```
🔒 SECURITY GATE: PASS ⚠️  (Grade: [GRADE], Score: [SCORE])

⚠️  High ([COUNT]):
   - [FINDING_DESCRIPTION] ([DOMAIN])
   - [FINDING_DESCRIPTION] ([DOMAIN])

Recommendation: Address High findings in next sprint.
```

---

## Format 3: Clean PASS (no Critical or High findings)

```
🔒 SECURITY GATE: PASS ✅  (Grade: [GRADE], Score: [SCORE])

✅ No critical or high severity issues detected.
```

---

## Gate Rules

- **FAIL** = any Critical finding exists. Deploy must not proceed.
- **PASS with warnings** = no Criticals, but one or more High findings. Deploy may proceed; findings should be scheduled for remediation.
- **Clean PASS** = no Critical or High findings. Deploy is clear.

## Placeholder Reference

| Placeholder | Value |
|-------------|-------|
| `[GRADE]` | Final letter grade after tier cap (A+ through F) |
| `[SCORE]` | Numeric score out of 100 |
| `[COUNT]` | Number of findings at that severity level |
| `[FINDING_DESCRIPTION]` | One-line summary of the finding |
| `[DOMAIN]` | Which audit domain surfaced the finding (e.g., auth, injection, secrets) |
