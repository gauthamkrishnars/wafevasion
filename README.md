# WAF Evasion Toolkit — XSS Payload Obfuscator

A Python tool that generates obfuscated XSS payloads to bypass character-based Web Application Firewall (WAF) filters.

## What It Does

This toolkit tests XSS payloads against simulated WAF regex rules and applies multiple evasion techniques to find bypasses. It demonstrates how simple pattern-matching WAFs can be circumvented using encoding and obfuscation.

## Evasion Techniques

| Technique | Description |
|-----------|-------------|
| HTML Entity Encoding | Converts characters to `&#NNN;` format |
| Case Randomization | Mixes uppercase/lowercase randomly |
| Null Byte Injection | Inserts `\x00` bytes to break regex |
| URL Encoding | Encodes special chars as `%XX` |
| Hex Tag Encoding | Replaces `<>` with `%3c%3e` |
| Double URL Encoding | Applies URL encoding twice |
| JS Chunk Insertion | Inserts null chars inside keywords |
| Whitespace Injection | Adds tabs/newlines inside tags |
| Mixed-Case Tags | Alternates case in tag names |
| Event Handler Break | Adds spaces in `onclick=` |
| Comment Splitting | Inserts `<!-->` mid-keyword |

## Filter Rules Detected

- `<script>` tags
- Event handlers (`onclick`, `onerror`, etc.)
- `javascript:` protocol
- `<img>` with events
- `<svg>` and `<iframe>` tags
- `eval()` calls
- `alert()`, `prompt()`, `confirm()`
- `document.cookie` access

## Requirements

- Python 3.6+
- No external dependencies

## Usage

```bash
python waf_bypass.py
```

### Output

```
======================================================================
  XSS Payload Obfuscator — Filter Evasion Toolkit
======================================================================

  [Basic Script]
    Original: <script>alert('XSS')</script>
    Blocked by: ScriptTag, AlertFunc
    >> EVASION via HTML Entity Encoding
       Payload: <&#115;cript>alert(&#39;XSS&#39;)&#60;/&#115;cript>
  ...
======================================================================
  TOTAL TESTS: 10
  Evaded:      10
  Caught:      0
  Success:     100.0%
======================================================================
```

## Interactive Mode

After automated tests, enter your own payloads:

```
Payload> <script>alert(1)</script>
Blocked by: ScriptTag, AlertFunc
Evaded with Case Randomization: <ScRiPt>alert(1)</ScRiPt>
```

## Limitations

- Simulated WAF — real WAFs use multi-layer detection (ML, behavioral analysis)
- Regex-only rules — advanced WAFs parse HTML DOM, not just text
- Educational purposes only — use responsibly for authorized security testing

## Project Structure

```
wafevasion/
├── waf_bypass.py   # Main evasion toolkit
└── README.md       # Documentation
```

## License

For educational and authorized security testing use only.
