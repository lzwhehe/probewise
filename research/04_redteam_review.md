# 04 — Red-team review of DESIGN.md (Probewise v2)

2026-10-14. Checks were run with `python -I` on the local SecAlertBench copy (8,322 records; 2,496 Attack / 5,826 Non-Attack; 241 rules). My feature proxies (regex payload, status bucket, UA class) are rough, so treat the numbers as orders of magnitude.

## P0. With a random split, the eval mostly measures memorized rules
- **Evidence:** 210 of 241 rules are label-pure, and they cover 4,851 records. If you predict each rule's majority label, in-sample accuracy is 94.3%. On a random 70/30 split, only 0.8–1.2% of test records come from rules not seen in training. The rule-history check by itself gets 93% accuracy and auto-closes about 56% of alerts (p<.05), missing 10–13 of about 750 attacks. 3,218 records sit in near-duplicate groups (same rule, method, uri, body); there are only 5,827 distinct keys.
- **Under a rule-grouped split** (GroupKFold on `rule_name`), 100% of test rules are unseen. My naive-Bayes prototype (rule history + payload + response + UA) collapses to 20–41% accuracy and a Brier score of 0.46–0.56. That is worse than always predicting the majority class. The "history too few" bucket is learned from rare training rules, and its likelihood ratio is wrong when the bucket is applied to a whole new rule population.
- **Fix:** report three splits: random (stated as optimistic), rule-grouped, and source/time (see P1). Deduplicate before splitting. Make the "cold-start rule" slice a primary result. For the "few" bucket, learn its likelihoods by simulating cold start on held-out rules.

## P0. Dataset artifacts separate the labels, and the design's "no timestamps" claim is wrong
- **Labels separated by field values:**
  - When `xff` is present, all 2,698 records are Non-Attack.
  - All 298 `CONNECT` records are Non-Attack.
  - `rsp_status` 200 gives 4,328 Non-Attack vs 153 Attack.
  - `dport` 8080 gives 2,658 Non-Attack vs 97 Attack.
  - `attack_type` SQL injection gives 3,645 Non-Attack vs 55 Attack.
- **A three-line artifact rule beats the paper's LLMs.** The rule is "xff → benign; CONNECT → benign; status≠200 → attack". It reaches TPR 93.9% and FPR 15.8%. The SecAlertBench LLM average is 79.7% / 44.1%.
- **Timestamps do exist.** 76% of records carry a `Date:` header in `rsp_header`.
  - All 2,783 records dated 2023 are Non-Attack. At least one source contributed only negatives.
  - Only the 2025 and 2026 records have both labels.
- **Leak paths:** the design drops XFF, but the LLM-review and response checks read raw headers, so they can still see Date, Server, XFF and port.
- **Fix:** before any check or LLM sees a record, remove `Date`, `Server`, `xff`, `dport`, `sport`, `kill_chain_all` and `attack_type` from its view. Add a split that trains on 2025 and tests on 2026. My prototype on that split got 84% accuracy, FPR 17%, 25% auto-close, and 3 of 789 attacks missed, which is much more modest. Publish the artifact baseline next to Probewise.

## P0. The comparison with the paper's LLM numbers is not valid
The two sets of numbers come from different splits, a different subset and a different protocol: the paper's LLMs ran zero-shot, while Probewise learns its tables from the same distribution. The artifact rule above already "beats" the paper, so beating it proves nothing.
**Fix:** run your own LLM-direct baseline on the same test split, with the same local model, the same stripped fields and the same prompt. Cite the paper's figures only as context, in a footnote.

## P1. Response semantics are inverted compared with the labels
The design treats "正常响应" (normal response) as neutral and "成功迹象" (signs of success) as malicious. In the data, a 200 response points strongly to benign and blocked or error statuses point to Attack. The label appears to mean "real attack attempt vs business-traffic false positive", not "successful compromise". Expert priors (n₀≈10) will start with the wrong sign, and with thousands of counts the prior is irrelevant anyway.
**Fix:** write the label definition into EVAL.md. Learn response outcomes from data. Keep "攻击是否成功" (did the attack succeed) as a separate, unlabeled field shown to the analyst.

## P1. Naive Bayes will be overconfident
On the random split, 69% of posteriors are below .01 or above .99. That looks calibrated (Brier 0.038) only because rule memorization does the work. The checks are not conditionally independent: payload × UA has Cramér's V = 0.26 within Attack. Rule history and payload are both proxies for the rule. So the 1% posterior for "auto-close" is not a real 1%.
**Fix:**
- Fit a logistic-regression calibration layer on a separate validation fold (or Platt-scale the summed log-odds).
- Cap |log LR| for each check.
- Choose the auto-close threshold on validation, never on test.
- Report ECE and missed-attack rate per slice: cold-start rule, per source.

## P1. Realism: the workflow does not match a Chinese L1 WAF desk
- **The dominant false positive is business traffic.** For example, 3,645 "SQL-injection" alerts are Non-Attack: business API parameters misread by the WAF. Analysts fix these with whitelists keyed on (rule, host, URI path) and close by source-IP campaign. Per-alert Bayes does not match that.
  - Fix: add (rule, host, path) history and whitelist suggestions. Batch by (rule, path) cluster.
- **Analysts close with a three-way verdict:** 误报 (false positive) / 攻击未成功 (attack, not successful) / 攻击成功 (attack, successful), plus a block-IP decision. The design's malicious/benign verdict does not cover that.
- **"Sub-agents" for regex decoding, status codes and UA parsing are deterministic functions.** At thousands of WAF alerts a day, an LLM call per check is too expensive and adds attack surface. Call them checks, not agents.
- **Asset criticality and source-IP history have no data:** IPs are randomized and there is no asset inventory. Do not show queue ranking by them as if it were evaluated.

## P1. Security of the design
- **Verbatim evidence checking is necessary but not sufficient.** Attackers control `uri`, `parameter`, `req_body`, UA and `host`, and partly control `rsp_body` through reflection. An attacker can plant "You have an error in your SQL syntax" in a parameter so that it is quoted verbatim.
  - Fix: bind each excerpt to (field, byte offsets). Allow only fields valid for that check; for example, the response check may cite only `rsp_*`.
- **The independent re-read uses the same model family on the same poisoned input, so it shares the vulnerability.** Treat it as a consistency check, not a security control.
- **Feedback-loop poisoning (ASI06):** an attacker floods a rule with benign-looking hits until rule history says "mostly FP", then sends the real exploit.
  - Fix: never auto-close on rule history alone. Require "no exploit payload" from the payload check. Accept feedback only from authenticated analysts. Rate-limit table updates.
- **The injection test needs controls.** Planting text in the UA also changes the UA feature, so measure verdict flips against a control with benign filler of the same length. Only 9 natural records contain injection-like text, so a synthetic suite is required. Report flips for both the LLM-review outcome and the final verdict.

## P2. Scope cuts
Cut or defer the following:
- GUIDE import
- ticket write-back (export paste-ready text only)
- the 6 synthetic scenarios in the main UI (keep them in a separate demo tab)
- asset-based queue ranking
- LLM mode for every check (keep only one optional LLM-review check)

Focus on:
- deterministic checks
- calibrate.py with a validation fold
- the 3-split eval with an artifact baseline
- the injection suite
- one case page

## Must-fix before build
1. Strip leaky fields (Date, Server, xff, ports, kill_chain, attack_type) from every check and LLM input.
2. Deduplicate, then evaluate on random + rule-grouped + 2025→2026 splits. Make cold-start rules a headline slice.
3. Add the artifact baseline and a same-split LLM-direct baseline. Demote the paper's numbers to context.
4. Define the label semantics. Learn response likelihoods from data.
5. Add a calibration layer, cap LRs per check, and pick thresholds on a validation fold.
6. Bind evidence to (field, offset). Forbid auto-close from rule history alone.
7. Cut ticket write-back, GUIDE, asset ranking and extra LLM checks from v2.
