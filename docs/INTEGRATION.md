# Integrating kemist output

Guide for people building rule engines, compliance scorecards,
dashboards, or any other tool that consumes kemist's JSON output.

## Contract

kemist is a **pure sensor**. It records what the server supports and
emits structured JSON. It does **not** emit compliance verdicts,
grades, severity rankings, or pass/fail judgments. That split is
deliberate and permanent.

Rule evaluation — "is this configuration SP 800-52 compliant?",
"does this cert meet CA/Browser Forum requirements?", "is this
cipher PCI-DSS weak?" — lives in downstream projects. Your project.

## Schema stability

The output schema is versioned semver-style (`schema_version` field):

| Change | Version bump | What consumers should do |
|---|---|---|
| New optional field | minor | Ignore unknown fields — your code keeps working |
| Field removed, type changed, required semantics changed | major | Pin on `schema_version` and refuse records from an unsupported major |
| New enum variant (e.g. new `validation_error` string) | minor | Handle unknown values gracefully |

**Pin the major.** A consumer built against schema v1 should refuse a
record with `schema_version: "2.x.x"` rather than silently misinterpret
it.

## The tri-state contract is load-bearing

Every probe-derived observation distinguishes four outcomes. See
[OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md#the-tri-state-contract-load-bearing)
for the full table.

**The most common integration mistake:** treating `value: null, method:
"not_probed"` as a negative signal. It isn't. The scanner didn't probe
— the server might support the thing, might not. Your rule engine has
three states, not two:

```python
match observation.value, observation.method:
    case True,  "probe":                        # affirmative
    case False, "probe":                        # negative
    case None,  "not_probed" | "not_applicable" | "error":
                                                # unknown
```

A policy that requires "EMS must be supported" against a TLS-1.3-only
server should not fail the server — on TLS 1.3 EMS is
`not_applicable`, not `supported: false`.

## Common queries

Below, assuming you've loaded one JSON record into a variable `r`.

### Did the scanner complete cleanly?

```python
# Scan never aborts (see scan_errors), but characterization can fail
completed = r["tls"]["negotiated"] is not None
errored   = len(r["errors"]) > 0
```

### Does the server negotiate a PQC hybrid by default?

```python
negotiated = r["tls"]["negotiated"]
is_pqc_hybrid = negotiated and "MLKEM" in (negotiated.get("group") or "")
```

### Does the server support a specific group?

```python
def group_state(r, name):
    obs = r["tls"]["groups"].get(name)
    if not obs:
        return "unknown"  # group not in scanner's target list
    if obs["method"] == "not_probed":
        return "not_probed"  # provider doesn't ship it
    return "supported" if obs["supported"] else "not_supported"

group_state(r, "X25519MLKEM768")
```

### Does the server accept weak TLS 1.2 CBC ciphers?

Trick question — kemist can't tell you directly. aws-lc-rs doesn't
ship CBC SHA-1 suites, so they appear as absent from
`tls.cipher_suites` rather than `supported: false`. Cross-reference
against a fuller registry:

```python
known_weak = {"0x0005", "0x000A", "0x002F", ...}  # full IANA table
probed = {e["iana_code"] for e in r["tls"]["cipher_suites"]["tls1_2"]}
unknown_weak = known_weak - probed
# unknown_weak contains suites your policy cares about that kemist didn't probe
```

### Cert validation

Three independent observations, not one:

```python
v = r["validation"]
chain_ok = v["chain_valid_to_webpki_roots"]["value"]
name_ok  = v["name_matches_sni"]["value"]
error    = v.get("validation_error")  # only set when chain invalid

# a wrong-host cert: chain_ok=True, name_ok=False, error=None
# an expired cert for the right name: chain_ok=False, name_ok=True, error="expired"
```

Don't collapse these into a single "cert OK" bool — your rule engine
needs both signals to distinguish name mismatch from an expired cert.

### Is this cert signed with a PQC algorithm?

```python
leaf = r["certificates"]["leaf"]
is_pqc = leaf and leaf["is_pqc_signature"]
pqc_name = leaf["signature_algorithm_name"] if is_pqc else None
# pqc_name is one of "ML-DSA-44", "ML-DSA-65", ..., "SLH-DSA-SHAKE-256f"
```

## Multi-target batches

`--format json` emits NDJSON (one record per line) — one record per
target. Stream it into your pipeline:

```bash
kemist --targets-file my-targets.txt --format json | \
  your-rule-engine --schema-version 1
```

For large batches: `--output-dir <path>` with `--format json-pretty`
writes one file per target (`<host>_<port>_<unixtime>.json`). Useful
for archiving.

## Error handling

kemist's `errors` field is a list, not a top-level exception. Even a
DNS-resolution failure produces a schema-valid record with the error
in `errors` and other fields stubbed. Consumers should:

1. Always check `schema_version` first
2. Check `errors` for DNS/connection failures
3. Gracefully handle `null` observations (tri-state contract)
4. Not assume any specific field set is always populated — only
   top-level fields and tri-state envelopes are guaranteed

## What to build on top

kemist feeds these kinds of downstream systems well:

- **Compliance scorecards** — SP 800-52, CNSA 2.0, PCI-DSS, etc.
  Map observations to rules, produce pass/fail per policy.
- **PQC readiness dashboards** — aggregate `tls.negotiated.group`,
  `tls.groups.*`, and `certificates.leaf.is_pqc_signature` across
  large fleets to track hybrid adoption.
- **Cert chain monitors** — alert on `validation_error == "expired"`
  or upcoming `validity_days`.
- **Regression detectors** — diff today's JSON against yesterday's,
  alert when a previously-`supported: true` cipher goes absent.

What kemist is NOT suited for:

- Vulnerability scanning in the traditional sense (we don't exploit;
  we observe). If your rules say "server is vulnerable to X", you're
  writing compliance logic — fine, but that's your project, not kemist's.
- Real-time monitoring at seconds-granularity. Each target takes 2–10
  seconds to scan depending on probe coverage.
