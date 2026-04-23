# kemist bundled data

Data files compiled into the kemist binary at build time. Each file
is committed for reproducible + offline-capable builds; refresh them
manually on a regular cadence.

## `hsts_preload_list.json`

**Source.** Chromium's `transport_security_state_static.json` from
`src/net/http/transport_security_state_static.json`. This is the list
that Chrome ships built into the browser; inclusion means "modern
browsers hard-refuse HTTP for this host."

**Upstream URL.**
<https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.json>

**Format.** JSON with JavaScript-style `//` line comments at the top.
Each entry has `{name, policy, mode, include_subdomains}`. kemist's
`build.rs` parses this with `json5` (comment-tolerant) and emits a
compile-time `phf::Map<&'static str, bool>` containing only
`mode == "force-https"` entries — HPKP-only pinning entries do not
register as HSTS-preloaded.

**Refresh command.**
```
curl -sL "https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.json?format=TEXT" \
  | base64 -D > data/hsts_preload_list.json
```

Commit the result. The binary grows by roughly `entry_count × 40 bytes`
(~3.5 MB today at ~92K entries).

**License.** BSD-style license per the Chromium source (see the
license header at the top of the bundled JSON file).

**Runtime override.** Operators who want a fresher snapshot without
rebuilding kemist can pass `--hsts-preload-list-path <path>` to load
a file with the same format at startup. Output carries
`http.preload_list_source: "runtime_override:<path>"` when active.
