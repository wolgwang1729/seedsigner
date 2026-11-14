#!/usr/bin/env python3
"""
Fuzz the signmessage QR decoder and derivation path parser.

This is a standalone tool; it only needs the project's normal runtime
dependencies.  It checks two properties:

1. Malformed QR payloads / derivation paths must never raise an unhandled
   exception.
2. If `parse_derivation_path()` reports `clean_match=True`, the path must be
   safe to hand to the rest of the signing flow (xpub derivation, address
   derivation, and message signing).

The second property is what turns a parser quirk into a crash in
`SeedSignMessageConfirmAddressView`.

Run from the repo root:

    python3 tools/fuzz_signmessage.py
    python3 tools/fuzz_signmessage.py --iterations 100000 --seed 1
    python3 tools/fuzz_signmessage.py --repro 'signmessage m/84h/0h/0h/0/2147483648 ascii:test'

Use `--strict` to also fail on non-crashing standards violations (for example,
an unhardened account component or a non-BIP44 path depth).
"""
from __future__ import annotations

import argparse
import logging
import random
import string
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if not (REPO_ROOT / "src" / "seedsigner").is_dir():
    REPO_ROOT = Path.cwd()
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from seedsigner.helpers import embit_utils
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.settings_definition import SettingsConstants

# The decoder logs a warning for every malformed payload; that is far too
# noisy for a fuzz run.
logging.disable(logging.CRITICAL)

SEED_BYTES = bytes(range(32))
BIP32_MAX_INDEX = 2**31

# Payloads that have been verified against the real flow (or that exercise a
# specific parser/decoder boundary).  Keeping them in the corpus means a
# regression is caught even if the random generator stops producing the shape.
CORPUS: list[str] = [
    # Happy path
    "signmessage m/84h/0h/0h/0/0 ascii:Hello Bitcoin!",
    "signmessage m/84'/0'/0'/0/0 ascii:Hello Bitcoin!",
    "signmessage m/84h/0h/0h/1/7 ascii:",
    "signmessage m/44h/0h/0h/0/0 ascii:legacy",
    "signmessage m/49h/0h/0h/0/0 ascii:nested",
    "signmessage m/86h/0h/0h/0/0 ascii:taproot",
    "signmessage m/84h/1h/0h/0/0 ascii:testnet",
    "signmessage m/84h/0h/0h/0/2147483647 ascii:max index",
    # Message content edge cases
    "signmessage m/84h/0h/0h/0/0 ascii:",
    "signmessage m/84h/0h/0h/0/0 ascii:hello   world",
    "signmessage m/84h/0h/0h/0/0 ascii:Time: 12:00:00",
    "signmessage m/84h/0h/0h/0/0 ascii:hello\nworld",
    "signmessage m/84h/0h/0h/0/0 ascii:hello\tworld",
    "signmessage m/84h/0h/0h/0/0 ascii:hello ascii:world",
    "signmessage m/84h/0h/0h/0/0 ascii:Привет мир",
    "signmessage m/84h/0h/0h/0/0 ascii:😀",
    # Decoder structure
    "signmessage",
    "signmessage m/84h/0h/0h",
    "signmessage m/84h/0h/0h asciimessage",
    "signmessage m/84h/0h/0h hex:123456",
    "signmessage_v2 m/84h/0h/0h ascii:test",
    "signmessage: m/84h/0h/0h ascii:test",
    "SIGNMESSAGE m/84h/0h/0h ascii:test",
    " signmessage m/84h/0h/0h/0/0 ascii:test",
    "signmessage  m/84h/0h/0h/0/0  ascii:test",
    "signmessage\tm/84h/0h/0h/0/0\tascii:test",
    "signmessage m ascii:",
    "signmessage m: ascii:x",
    "signmessage signmessage ascii:x",
    "signmessage m/84h/0h/ascii:test/0/0 ascii:Real message content",
    # Parser depth / shape
    "signmessage m/84h/0h/0h/0 ascii:test",
    "signmessage m/84h/0h/0h/0/0/0 ascii:test",
    "signmessage m/84h/0h/0h/0/0/0/0 ascii:test",
    "signmessage m/84h/0h/0/0/0 ascii:test",
    "signmessage m/84h/0h/0/0/0/0 ascii:test",
    # Out-of-range / malformed child indexes
    "signmessage m/84h/0h/0h/0/2147483648 ascii:test",
    "signmessage m/84h/0h/0h/0/999999999999999999999999 ascii:test",
    "signmessage m/84h/0h/0h/0/² ascii:test",
    "signmessage m/84h/0h/0h/0/٠ ascii:test",
    "signmessage m/84h/0h/0h/0/१२ ascii:test",
    "signmessage m/84h/0h/0h/0/１２ ascii:test",
    "signmessage m/84h/0h/0h/0/-1 ascii:test",
    "signmessage m/84h/0h/0h/0/+1 ascii:test",
    # Malformed account / purpose / coin components
    "signmessage m/84h/0h/invalid_acc/0/0 ascii:test",
    "signmessage m/84h/0h/999999999999999999999999h/0/0 ascii:test",
    "signmessage m/84h/0h/notah/0/0 ascii:test",
    "signmessage m/84h/0h/-1/0/0 ascii:test",
    "signmessage m/84h/0h/h/0/0 ascii:test",
    "signmessage m/84h/0h/./0/0 ascii:test",
    "signmessage m/84h/0h/../0/0 ascii:test",
    "signmessage m/84h/0h//0/0 ascii:test",
    "signmessage m/notah/0h/0h/0/0 ascii:test",
    "signmessage m/84h/notah/0h/0/0 ascii:test",
    # Uppercase / mixed hardening markers
    "signmessage m/84H/0h/0h/0/0 ascii:test",
    "signmessage m/84'/0h/0'h/0/0 ascii:test",
    "signmessage m/84h/0h/0h/0/0h ascii:test",
    # Custom derivations
    "signmessage m/99h/0h/0h/0/0 ascii:test",
    "signmessage m/45h/0h/0h/0/0 ascii:test",
    "signmessage m/99h/0/0 ascii:test",
    # Multisig (handled by the Start view as a redirect)
    "signmessage m/48h/0h/0h/2h/0/0 ascii:test",
    "signmessage m/48'/0'/0'/2' ascii:test",
    # Garbage after a valid prefix
    "signmessage m/84h/0h/0h/0/0 ascii:test\x00",
    "signmessage m/84h/0h/0h/0/0 ascii:test\r\n",
    "signmessage m/84h/0h/0h/0/0",
    "signmessage m/84h/0h/0h/0/0 ascii",
]


@dataclass(frozen=True)
class Finding:
    severity: str  # "FAIL" or "WARN"
    key: str
    case: str
    detail: str
    why: str

    def as_line(self) -> str:
        return f"[{self.severity}] {self.key}: {self.case!r} ({self.detail})"


def _failure(key: str, case: str, detail: str, why: str) -> Finding:
    return Finding("FAIL", key, case, detail, why)


def _warning(key: str, case: str, detail: str, why: str) -> Finding:
    return Finding("WARN", key, case, detail, why)


def _is_ascii_digits(value: str) -> bool:
    return value.isascii() and value.isdigit()


def _check_parsed_path(path: str, details: dict) -> list[Finding]:
    """Checks that only make sense once the parser has claimed a clean match."""
    findings: list[Finding] = []
    if not details.get("clean_match"):
        return findings

    sections = path.replace("'", "h").split("/")

    if details.get("script_type") == SettingsConstants.CUSTOM_DERIVATION:
        findings.append(_failure(
            "flow.custom_rejected",
            path,
            f"clean_match=True, script_type={details.get('script_type')!r}",
            "SeedSignMessageStartView accepts this path, then "
            "SeedSignMessageConfirmAddressView raises for CUSTOM_DERIVATION.",
        ))
        # The upstream code raises before deriving anything; stop here so the
        # same root cause is not reported three times.
        return findings

    if len(sections) != 5:
        findings.append(_warning(
            "shape.depth",
            path,
            f"clean_match=True at depth {len(sections)}",
            "The standard single-sig address path is exactly 5 components; "
            "the extra/missing components are derived as if they were part of "
            "the standard path.",
        ))

    wallet_path = details.get("wallet_derivation_path")
    if not wallet_path:
        findings.append(_warning(
            "shape.wallet_path",
            path,
            "clean_match=True but wallet_derivation_path is empty",
            "ConfirmAddressView passes wallet_derivation_path to get_xpub().",
        ))
        return findings

    wallet_sections = wallet_path.replace("'", "h").split("/")
    if len(wallet_sections) != 4:
        findings.append(_warning(
            "shape.wallet_depth",
            path,
            f"wallet_derivation_path={wallet_path!r}",
            "The wallet path should be m/purpose'/coin'/account'.",
        ))
    elif not wallet_sections[3].endswith("h"):
        findings.append(_warning(
            "shape.account_unhardened",
            path,
            f"wallet_derivation_path={wallet_path!r}",
            "BIP-44/49/84/86 account components must be hardened.",
        ))

    for component in wallet_sections[1:]:
        core = component[:-1] if component.endswith("h") else component
        if not _is_ascii_digits(core):
            findings.append(_warning(
                "shape.wallet_component",
                path,
                f"wallet_derivation_path={wallet_path!r}, component={component!r}",
                "get_xpub()/embit cannot parse this account component.",
            ))

    index = details.get("index")
    if not isinstance(index, int) or isinstance(index, bool):
        findings.append(_warning(
            "shape.index_type",
            path,
            f"index={index!r}",
            "ConfirmAddressView passes index to get_single_sig_address().",
        ))
    elif not (0 <= index < BIP32_MAX_INDEX):
        findings.append(_warning(
            "shape.index_range",
            path,
            f"index={index}",
            "BIP32 non-hardened child indexes must be < 2^31; embit raises "
            "when the index is used with an xpub.",
        ))

    # Now run the same operations as the views.  This is deliberately not
    # wrapped in one try/except: each operation has a distinct failure mode.
    try:
        xpub = embit_utils.get_xpub(SEED_BYTES, wallet_path)
    except Exception as exc:
        findings.append(_failure(
            f"flow.xpub:{type(exc).__name__}",
            path,
            f"{type(exc).__name__}: {exc}",
            "SeedSignMessageConfirmAddressView calls get_xpub(wallet_path).",
        ))
        return findings

    network = details["network"]
    if isinstance(network, list):
        # SeedSignMessageStartView accepts a list for testnet/regtest and
        # SeedSignMessageConfirmAddressView resolves it from Settings.
        network = SettingsConstants.TESTNET

    try:
        embit_utils.get_single_sig_address(
            xpub=xpub,
            script_type=details["script_type"],
            index=index,
            is_change=details["is_change"],
            embit_network=SettingsConstants.map_network_to_embit(network),
        )
    except Exception as exc:
        findings.append(_failure(
            f"flow.address:{type(exc).__name__}",
            path,
            f"{type(exc).__name__}: {exc}",
            "SeedSignMessageConfirmAddressView calls get_single_sig_address().",
        ))

    try:
        embit_utils.sign_message(SEED_BYTES, path, b"fuzz")
    except Exception as exc:
        findings.append(_failure(
            f"flow.sign:{type(exc).__name__}",
            path,
            f"{type(exc).__name__}: {exc}",
            "SeedSignMessageSignedMessageQRView calls sign_message().",
        ))

    return findings


def analyze_path(path: str, strict: bool = False) -> list[Finding]:
    try:
        details = embit_utils.parse_derivation_path(path)
    except NotImplementedError:
        # This is an intentional, handled signal for BIP-48 multisig paths.
        return []
    except Exception as exc:
        return [_failure(
            f"parser.exception:{type(exc).__name__}",
            path,
            f"{type(exc).__name__}: {exc}",
            "parse_derivation_path() should return clean_match=False for "
            "malformed input rather than raising.",
        )]

    if not isinstance(details, dict):
        return [_failure(
            "parser.return_type",
            path,
            f"returned {type(details).__name__}",
            "parse_derivation_path() should always return a dict.",
        )]

    findings = _check_parsed_path(path, details)
    if strict:
        return findings
    return [finding for finding in findings if finding.severity == "FAIL"]


def analyze_payload(payload: str, strict: bool = False) -> list[Finding]:
    findings: list[Finding] = []

    decoder = DecodeQR()
    try:
        status = decoder.add_data(payload)
    except Exception as exc:
        return [_failure(
            f"decoder.exception:{type(exc).__name__}",
            payload,
            f"{type(exc).__name__}: {exc}",
            "DecodeQR.add_data() must not raise on untrusted QR data.",
        )]

    if status != DecodeQRStatus.COMPLETE:
        return findings

    if not decoder.is_sign_message:
        findings.append(_failure(
            "decoder.wrong_type",
            payload,
            f"status=COMPLETE, is_sign_message={decoder.is_sign_message}",
            "A completed signmessage decoder should report is_sign_message.",
        ))
        return findings

    try:
        data = decoder.get_qr_data()
    except Exception as exc:
        return [_failure(
            f"decoder.get_qr_data:{type(exc).__name__}",
            payload,
            f"{type(exc).__name__}: {exc}",
            "get_qr_data() must not raise after COMPLETE.",
        )]

    path = data.get("derivation_path")
    message = data.get("message")
    if not isinstance(path, str) or not isinstance(message, str):
        findings.append(_failure(
            "decoder.data_types",
            payload,
            f"derivation_path={path!r}, message={message!r}",
            "The decoder contract is dict(derivation_path=str, message=str).",
        ))
        return findings

    # Run the parser exactly like SeedSignMessageStartView does.
    try:
        details = embit_utils.parse_derivation_path(path)
    except NotImplementedError:
        return findings
    except Exception as exc:
        findings.append(_failure(
            f"parser.exception:{type(exc).__name__}",
            payload,
            f"path={path!r}: {type(exc).__name__}: {exc}",
            "The Start view catches this and redirects, but the parser should "
            "still return clean_match=False for malformed input.",
        ))
        return findings

    findings.extend(_check_parsed_path(path, details))

    # The message itself must be encodable before the signing view runs.
    if details.get("clean_match"):
        try:
            message.encode()
        except Exception as exc:
            findings.append(_failure(
                f"flow.message_encode:{type(exc).__name__}",
                payload,
                f"{type(exc).__name__}: {exc}",
                "SeedSignMessageSignedMessageQRView calls message.encode().",
            ))

    if strict:
        return findings
    return [finding for finding in findings if finding.severity == "FAIL"]


# ---------------------------------------------------------------------------
# Input generation
# ---------------------------------------------------------------------------

PURPOSES = ["44h", "49h", "84h", "86h", "48h", "99h", "45h", "84H", "84'", "84", "notah", "", "2147483648h"]
COINS = ["0h", "1h", "0", "1", "2h", "", "0H", "notah", "999999999999999999999999h"]
ACCOUNTS = [
    "0h", "1h", "0", "1", "2h", "", "0H", "notah", "invalid_acc",
    "2147483648h", "999999999999999999999999h", "-1", "-1h", "h", ".",
    "..", " 0h", "0h ", "+0", "0x0",
]
CHANGES = ["0", "1", "2", "0h", "1h", "", "00", "01", "+0", "-0", "٠", "١"]
INDEXES = [
    "0", "1", "2", "2147483647", "2147483648", "4294967295",
    "999999999999999999999999", "²", "٠", "١", "१२", "１２", "",
    "-1", "+1", "0x1", "1e3", " 1", "1 ", "00", "01",
]
ROOTS = ["m", "M", "", " m", "m ", "m/", "./m", "mm"]


def _random_component(rng: random.Random, pool: list[str]) -> str:
    if rng.random() < 0.70:
        return rng.choice(pool)
    alphabet = "mM/0123456789hH'²٠١１２invalid_acc_-+ ."
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 10)))


def generate_path(rng: random.Random) -> str:
    if rng.random() < 0.25:
        # Completely random path-ish text.
        alphabet = "mM/0123456789hH'²٠١invalid_acc_-+ ."
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))

    depth = rng.choices([2, 3, 4, 5, 6, 7, 8], weights=[2, 4, 5, 50, 12, 10, 2])[0]
    parts = [rng.choice(ROOTS) if rng.random() < 0.15 else "m"]
    if depth >= 1:
        parts.append(_random_component(rng, PURPOSES))
    if depth >= 2:
        parts.append(_random_component(rng, COINS))
    if depth >= 3:
        parts.append(_random_component(rng, ACCOUNTS))
    if depth >= 4:
        parts.append(_random_component(rng, CHANGES))
    if depth >= 5:
        parts.append(_random_component(rng, INDEXES))
    while len(parts) < depth:
        parts.append(_random_component(rng, INDEXES + CHANGES + ACCOUNTS))

    path = "/".join(parts)
    if rng.random() < 0.05:
        path += "/"
    if rng.random() < 0.05:
        path = path.replace("/", "//", 1)
    return path


MESSAGES = [
    "", "hello", "hello world", "Time: 12:00:00", "a" * 100,
    "Привет мир", "😀", "line1\nline2", "tab\there", "ascii:inside",
    '{"height":841407,"lightning_bolt12":"lno1..."}', "\x00", "\r\n",
]


def generate_message(rng: random.Random) -> str:
    if rng.random() < 0.75:
        return rng.choice(MESSAGES)
    alphabet = string.printable + "éü😀Привет\x00"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))


def generate_payload(rng: random.Random) -> str:
    if rng.random() < 0.10:
        # Random garbage, but keep the signmessage prefix so DecodeQR selects
        # the decoder under test.
        alphabet = string.printable + "éü😀²٠١"
        return "signmessage" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))

    path = generate_path(rng)
    message = generate_message(rng)

    template = rng.choices(
        ["valid", "no_format", "wrong_format", "no_message", "wrong_command",
         "extra_parts", "spaces", "format_in_path", "duplicate_command"],
        weights=[60, 6, 4, 4, 4, 4, 8, 5, 5],
    )[0]

    if template == "valid":
        return f"signmessage {path} ascii:{message}"
    if template == "no_format":
        return f"signmessage {path} {message}"
    if template == "wrong_format":
        return f"signmessage {path} {rng.choice(['hex', 'utf8', 'base64', ''])}:{message}"
    if template == "no_message":
        return f"signmessage {path}"
    if template == "wrong_command":
        return f"{rng.choice(['signmessage_v2', 'SIGNMESSAGE', 'sign_message', 'signmessage:'])} {path} ascii:{message}"
    if template == "extra_parts":
        return f"signmessage {path} ascii:{message} {generate_message(rng)}"
    if template == "spaces":
        sep = rng.choice(["  ", "\t", " \t "])
        return f"signmessage{sep}{path}{sep}ascii:{message}"
    if template == "format_in_path":
        return f"signmessage {path}/ascii:test ascii:{message}"
    if template == "duplicate_command":
        return f"signmessage signmessage {path} ascii:{message}"
    raise AssertionError(template)


# ---------------------------------------------------------------------------
# Shrinking / reporting
# ---------------------------------------------------------------------------


def _finding_keys(findings: list[Finding]) -> set[str]:
    return {finding.key for finding in findings}


def shrink(case: str, analyzer, key: str, max_steps: int = 200) -> str:
    """Delete characters while the same failure key survives."""
    steps = 0
    changed = True
    while changed and steps < max_steps:
        changed = False
        for index in range(len(case)):
            candidate = case[:index] + case[index + 1:]
            steps += 1
            if key in _finding_keys(analyzer(candidate, strict=True)):
                case = candidate
                changed = True
                break
    return case


@dataclass
class RunStats:
    cases: int = 0
    findings: int = 0


def _print_findings(findings: list[Finding], mode: str) -> None:
    for finding in findings:
        print(f"\n[{finding.severity}] {finding.key}")
        print(f"  {mode}: {finding.case!r}")
        print(f"  detail: {finding.detail}")
        print(f"  why:    {finding.why}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20000, help="random cases per target (default: 20000)")
    parser.add_argument("--seed", type=int, default=1, help="PRNG seed (default: 1)")
    parser.add_argument("--max-failures", type=int, default=20, help="stop after this many unique failures (default: 20)")
    parser.add_argument("--no-shrink", action="store_true", help="do not minimize failing inputs")
    parser.add_argument("--strict", action="store_true", help="also report non-crashing standards violations")
    parser.add_argument("--repro", metavar="INPUT", help="run one payload or path and print all findings")
    parser.add_argument("--corpus-only", action="store_true", help="only replay the built-in corpus")
    parser.add_argument("--verbose", action="store_true", help="print every generated case")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)

    if args.repro:
        analyzer = analyze_payload if args.repro.startswith("signmessage") else analyze_path
        findings = analyzer(args.repro, strict=True)
        if not findings:
            print("No findings.")
            return 0
        _print_findings(findings, "input")
        return 1

    seen: dict[str, Finding] = {}
    stats = RunStats()

    def record(findings: list[Finding]) -> bool:
        for finding in findings:
            stats.findings += 1
            if finding.key not in seen:
                candidate = finding
                if not args.no_shrink:
                    analyzer = analyze_payload if finding.case.startswith("signmessage") else analyze_path
                    shrunk = shrink(finding.case, analyzer, finding.key)
                    for shrunk_finding in analyzer(shrunk, strict=True):
                        if shrunk_finding.key == finding.key:
                            candidate = shrunk_finding
                            break
                seen[candidate.key] = candidate
        return len(seen) >= args.max_failures

    print("SeedSigner signmessage hardening fuzzer")
    print(f"  repo:       {REPO_ROOT}")
    print(f"  seed:       {args.seed}")
    print(f"  iterations: {0 if args.corpus_only else args.iterations} per target")
    print(f"  strict:     {args.strict}")

    print("\nReplaying corpus ...")
    for payload in CORPUS:
        stats.cases += 1
        if args.verbose:
            print(f"  {payload!r}")
        if record(analyze_payload(payload, args.strict)):
            break

    if not args.corpus_only and len(seen) < args.max_failures:
        print("\nFuzzing derivation paths ...")
        for _ in range(args.iterations):
            path = generate_path(rng)
            stats.cases += 1
            if args.verbose:
                print(f"  {path!r}")
            if record(analyze_path(path, args.strict)):
                break

    if not args.corpus_only and len(seen) < args.max_failures:
        print("\nFuzzing decoder payloads ...")
        for _ in range(args.iterations):
            payload = generate_payload(rng)
            stats.cases += 1
            if args.verbose:
                print(f"  {payload!r}")
            if record(analyze_payload(payload, args.strict)):
                break

    fails = [finding for finding in seen.values() if finding.severity == "FAIL"]
    warns = [finding for finding in seen.values() if finding.severity == "WARN"]

    print(f"\nRan {stats.cases} cases, produced {stats.findings} findings "
          f"({len(fails)} unique FAIL, {len(warns)} unique WARN).")
    if seen:
        print("\nUnique findings:")
        _print_findings(list(seen.values()), "repro")

    if fails:
        print("\nRESULT: FAIL")
        return 1
    if warns and args.strict:
        print("\nRESULT: FAIL (strict mode)")
        return 1
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
