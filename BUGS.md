# Known Bugs

## [Severity: High] CEF "streaming" loads entire file into memory
- **File:** threatlens/parsers/__init__.py:55
- **Issue:** `stream_events()` for CEF calls `load_cef_events()` (in-memory loader) instead of a true generator, defeating streaming and OOM-ing on large CEF files.
- **Repro:** Call `stream_events(path, "cef")` on a multi-GB CEF file — entire file is loaded.
- **Fix:** Implement `stream_cef_events()` as a line-by-line generator in `cef_parser.py` (mirroring `syslog_parser.stream_syslog_events`) and call it here.

## [Severity: High] IP regex accepts invalid octets
- **File:** threatlens/parsers/syslog_parser.py:68
- **Issue:** Regex `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})` matches values like `999.999.999.999`, allowing malformed IPs into `source_ip`.
- **Repro:** Parse a syslog line containing `999.999.999.999` — it is stored as a valid source IP.
- **Fix:** Validate each octet ≤ 255 (use `ipaddress.ip_address()` after regex capture, or a stricter pattern).

## [Severity: Medium] Allowlist rule_name uses substring match instead of equality
- **File:** threatlens/allowlist.py:37
- **Issue:** Uses `not in` (substring) rather than equality; an entry `"Brute"` suppresses every rule whose name contains `"Brute"`.
- **Repro:** Add allowlist entry `{rule_name: "Brute"}` — it silences "Brute-Force Detected", "Brute Force Attack", etc.
- **Fix:** Change to equality: `entry["rule_name"].lower() != alert.rule_name.lower()`.

## [Severity: Medium] Discovery detector skips overlapping windows
- **File:** threatlens/detections/discovery.py:99
- **Issue:** `i += len(window)` after a match jumps past events that could start their own window, missing detections.
- **Repro:** Five events all within the window threshold — only one alert fires; remaining events are never evaluated as window starters.
- **Fix:** Advance by `i += 1` (or use the deduplication pattern from `utils.find_dense_windows`).

## [Severity: Low] is_private_ip silently returns False for malformed IPs
- **File:** threatlens/utils.py:69-77
- **Issue:** `ipaddress.ip_address()` raising `ValueError` is caught and `False` returned, indistinguishable from a valid public IP.
- **Repro:** `is_private_ip("999.999.999.999")` returns `False` instead of flagging invalid input.
- **Fix:** Add an explicit validity check or raise/log invalid input before the private-range check.
