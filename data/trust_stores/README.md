# kemist trust-store bundles

Four bundles compiled into the binary. Each is a PEM
concatenation of trust-anchor certificates. Comments (lines
starting with `#`) are preserved in the source file for
documentation but stripped at load time.

| Name (CLI) | File | Source | Notes |
|---|---|---|---|
| `webpki-roots` | (embedded via crate) | Mozilla CCADB via [webpki-roots](https://crates.io/crates/webpki-roots) | Refreshed by crate updates. Does not live in `data/`. |
| `microsoft` | `microsoft_ccadb.pem` | CCADB V5 (Microsoft Status) + AllCertificatePEMs by decade | 188 roots where CCADB records `Microsoft Status = Included AND TLS Capable = True`. PEMs pulled from CCADB's decade-partitioned full-cert dump and filtered to the Microsoft set. 66 roots are Microsoft-only (not in Mozilla), 122 overlap with Mozilla. |
| `apple` | `apple_pki.pem` | macOS System Roots keychain | Apple's TLS trust store — what Safari/iOS trust for server certs. Extracted from `/System/Library/Keychains/SystemRootCertificates.keychain` via `security find-certificate -a -p`. ~160 roots covering DigiCert, ISRG, Let's Encrypt, Entrust, GlobalSign, etc. Refresh from any modern macOS. NOT to be confused with Apple's own PKI roots at `apple.com/certificateauthority/` (those sign Apple services only). |
| `us-fpki-common` | `us_fpki_common.pem` | FCPCA G2 + SIA-discovered agency intermediates | Root + 11 agency intermediates (DigiCert Federal SSP, Entrust Federal Root, Federal Bridge CA G4, State Dept AD Root, Treasury Root, WidePoint ORC). See Refresh section — SIA URL read from the root cert itself, not hardcoded. |
| `us-dod` | `us_dod.pem` | `dl.dod.cyber.mil` PKI-PKE bundle | DoD Root CA 3/4/5/6 + intermediates (49 certs from `unclass-certificates_pkcs7_DoD.zip`). |

## Loading

At startup, kemist parses each file via `rustls_pemfile`, feeds
the resulting DER certs into a `rustls::RootCertStore`, and builds
a `WebPkiServerVerifier` per store. Comments + whitespace outside
`-----BEGIN CERTIFICATE-----` blocks are ignored. Empty bundles
produce `chain_valid_to_<name>_roots: {method: not_probed, reason:
"trust_store_empty"}` — the probe knows about the store but has no
anchors to validate against.

## Runtime overrides

- `--trust-store <name>:<path>` replaces a compiled-in bundle with
  the file at `<path>`. Accepted names: `webpki-roots`,
  `microsoft`, `apple`, `us-fpki-common`, `us-dod`. Output surfaces
  `validation.trust_store_sources.<name>: "runtime_override:<path>"`.
- `--extra-trust-store <name>:<path>` adds a new named bundle (not
  a replacement). Name must be lowercase-ASCII + hyphens; must not
  collide with a compiled name. Surfaces under
  `validation.chain_valid_to_custom_roots.<name>`.

## Automated refresh (`--update-trust-stores`)

Run `kemist --update-trust-stores` to fetch the latest bundles
from upstream (Microsoft via CCADB, DoD via DISA, FPKI via fcpca)
and write them to the platform cache directory:

| Platform | Cache root |
|---|---|
| Linux | `$XDG_CACHE_HOME/kemist/` (default `~/.cache/kemist/`) |
| macOS | `~/Library/Caches/kemist/` |
| Windows | `%LOCALAPPDATA%\kemist\cache\` |

Trust-store files land in `$cache/trust_stores/*.pem`; HSTS
preload refresh via `kemist --update-hsts-preload` lands in
`$cache/hsts_preload_list.json`. A sibling `$cache/manifest.json`
records per-bundle provenance (source URL, fetched_at timestamp,
SHA-256 hash, entry count, upstream version when available).

The scanner reads cache-first at startup: cache file + manifest
SHA-256 match → use cache. Falls back to the compile-time bundle
when the cache is empty, unverifiable, or corrupt. Output
`validation.trust_store_sources.<name>` surfaces `compiled_in` /
`cache_refreshed:<path>` / `runtime_override:<path>` so consumers
know which snapshot drove each observation.

Apple is the one exception — no portable way to extract the
macOS System Roots keychain from a non-Mac host. On macOS, refresh
manually with `security find-certificate -a -p` (see the "Apple"
section below); on other platforms, rely on the compile-time
bundle or supply one via `--trust-store apple:<path>`.

webpki-roots is refreshed via `cargo update` — it's a Rust crate,
not an on-disk bundle.

## Refresh

### Apple

The Apple trust store Safari / iOS consult for TLS server
validation is the macOS System Roots keychain — a superset of
public-CA roots, NOT Apple's own PKI roots. Extract from any
modern macOS:

```
{
    echo "# Apple TLS trust store — PEM export of macOS System Roots."
    echo "# Extracted $(date -u +%Y-%m-%dT%H:%M:%SZ) from"
    echo "# /System/Library/Keychains/SystemRootCertificates.keychain"
    echo ""
    security find-certificate -a -p \
        /System/Library/Keychains/SystemRootCertificates.keychain
} > data/trust_stores/apple_pki.pem
```

Apple updates this keychain with each macOS / Safari security
release. Running the command on a recently-patched Mac is
sufficient — no Apple-internal access needed. For Linux / Windows
hosts, an equivalent export lives at
<https://opensource.apple.com/source/security_certificates/>
(match the version to the macOS release you want to track).

Note: what's at <https://www.apple.com/certificateauthority/> is
**Apple's own PKI** (signing Apple services, code signing, etc.)
— these do NOT trust third-party TLS CAs like DigiCert or ISRG.
Using that bundle instead would reject almost every real-world
server cert. This is a common first-time mistake; documenting
explicitly to avoid repeats.

### US FPKI Common

The FPKI bundle is Federal Common Policy CA G2 (root) **plus the
agency intermediates signed under it**, discovered via the root
cert's own Subject Information Access extension (RFC 5280
§4.2.2.2). No hardcoded URL — read SIA off the root:

```
# 1. Fetch the Federal Common Policy CA G2 root.
curl -sL "https://http.fpki.gov/fcpca/fcpcag2.crt" -o /tmp/fcpcag2.crt

# 2. Extract the SIA CA-Repository URI from the root itself.
SIA_URL=$(openssl x509 -in /tmp/fcpcag2.crt -inform DER -noout -text \
    | grep -A 2 "Subject Information Access" \
    | grep -oE "http://[^ ]+\.p7c" | head -1)
# As of the current snapshot:
#   http://repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c

# 3. Fetch the p7c bundle of intermediates and convert to PEM.
curl -sL "$SIA_URL" -o /tmp/fcpca_sia.p7c
openssl pkcs7 -inform DER -in /tmp/fcpca_sia.p7c -print_certs \
    -out /tmp/fcpca_sia.pem

# 4. Concatenate root + intermediates into the vendored bundle.
{
    openssl x509 -inform DER -in /tmp/fcpcag2.crt -outform PEM
    cat /tmp/fcpca_sia.pem
} > data/trust_stores/us_fpki_common.pem
```

Why include the SIA-chained intermediates? FPKI-issued servers
commonly omit one or more intermediates from their TLS
`Certificate` flight, especially for cross-agency chains. Treating
the agency CAs as trust anchors lets kemist's validation complete
where strict root-only validation would fail. This is a deliberate
FPKI-ecosystem pragmatism, not a generic trust-store decision —
other bundles (Mozilla, Apple) stay root-only.

### Microsoft CCADB

Rebuild by joining two CCADB endpoints: the V5 metadata report
(tells us *which* roots Microsoft trusts via `Microsoft Status`)
and the all-certs-by-decade PEM dump (gives us the bytes).

```
# 1. Microsoft Status + TLS Capable metadata from V5.
curl -sL -A "Mozilla/5.0" \
    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5" \
    -o /tmp/ccadb_all.csv

# 2. PEM bytes for every CCADB cert, partitioned by NotBeforeDecade.
#    Each pull is parameterized; iterate the decades.
for decade in 1990 2000 2010 2020; do
    curl -sL -A "Mozilla/5.0" \
        "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeDecade=$decade" \
        -o /tmp/pems_$decade.csv
done

# 3. Python intersect (Microsoft-included TLS roots × available PEMs).
python3 <<'PY'
import csv
msft = set()
with open('/tmp/ccadb_all.csv', newline='') as f:
    for row in csv.DictReader(f):
        if (row.get('Microsoft Status', '').strip() == 'Included'
                and row.get('TLS Capable', '').strip() == 'True'):
            fp = row.get('SHA-256 Fingerprint', '').replace(':', '').upper()
            if fp:
                msft.add(fp)
pems = {}
for d in (1990, 2000, 2010, 2020):
    with open(f'/tmp/pems_{d}.csv', newline='') as f:
        for row in csv.DictReader(f):
            fp = row.get('SHA-256 Fingerprint', '').replace(':', '').upper()
            p = row.get('X.509 Certificate (PEM)', '').strip()
            if fp and p:
                pems[fp] = p
with open('data/trust_stores/microsoft_ccadb.pem', 'w') as out:
    out.write(f'# Microsoft CCADB TLS trust store — {len(msft)} roots.\n')
    out.write(f'# Source: CCADB V5 (Microsoft Status filter) × AllCertificatePEMs by decade.\n\n')
    for fp in sorted(msft & set(pems.keys())):
        out.write(pems[fp].strip().strip("'\"") + '\n')
PY
```

CCADB's `AllCertificatePEMsCSVFormat` is **not Microsoft-specific**
on its own — it's the full CCADB cert dump. Microsoft-specificity
comes from the V5 metadata's `Microsoft Status` column; the PEM
endpoint just supplies bytes for whichever subset the V5 filter
selects.

Current snapshot: 188 roots. Divergence against Mozilla: 66
Microsoft-only roots (primarily commercial / government CAs
Mozilla excludes from its program) and 16 Mozilla-only roots.

### US DoD

DISA's PKI-PKE portal publishes the unclassified bundle at a
curl-able URL. The server 403/404s default curl User-Agents —
send a browser-style UA to fetch.

```
curl -sL -A "Mozilla/5.0" \
    "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip" \
    -o /tmp/dod.zip
unzip -o /tmp/dod.zip -d /tmp/dod
openssl pkcs7 -inform PEM \
    -in /tmp/dod/Certificates_PKCS7_v5_14_DoD/Certificates_PKCS7_v5_14_DoD.pem.p7b \
    -print_certs -out /tmp/dod_all.pem
# Prepend a provenance header + copy into data/
{
    echo "# US DoD PKI trust store."
    echo "# Source: https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip"
    echo "# Extracted $(date -u +%Y-%m-%dT%H:%M:%SZ) from Certificates_PKCS7_v5_14_DoD.pem.p7b"
    echo ""
    cat /tmp/dod_all.pem
} > data/trust_stores/us_dod.pem
```

Current snapshot: 49 certs — DoD Root CA 3/4/5/6 plus the PKI
intermediates signed under each. Root CAs 3 and 4 are RSA
(sha256WithRSAEncryption); Root CA 5 is ECDSA P-384. Root CA 6 is
being rolled out as the PQ-forward-compatible replacement.

The bundle version (`v5_14` in the filename) changes with each DoD
release — check the ZIP contents after fetch; the `.sha256` file
next to the PEM is the DoD's own integrity signature.

DoD federal servers that chain through the Federal Bridge CA G4
validate under `us_fpki_common.pem` too — so for mixed-chain
targets, both stores may light up. `us-dod` matters for pure-DoD
roots (Root CA 3/4/5/6-signed chains with no Federal Bridge hop).

## Commit hygiene

- Commit PEM updates as a single commit per bundle; put the
  upstream snapshot date in the commit message.
- Run `openssl x509 -noout -subject -in <file>` across every cert
  in the bundle to spot-check before committing.
- Binary size grows ~2 bytes per PEM line — 4 MB combined for 500
  roots is common. Acceptable.
