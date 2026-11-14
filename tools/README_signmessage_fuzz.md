# `signmessage` Hardening Fuzzer

Standalone fuzzer for the `signmessage` QR decoder and derivation-path parser.
This is a tool-only branch based on `dev`: it does not change production code.

To run it against a PR branch, cherry-pick the fuzzer commit or copy `tools/fuzz_signmessage.py` onto that branch.

## Run It

```bash
python3 tools/fuzz_signmessage.py
python3 tools/fuzz_signmessage.py --iterations 100000 --seed 1
python3 tools/fuzz_signmessage.py --repro 'signmessage m/84h/0h/0h/0/2147483648 ascii:test'
python3 tools/fuzz_signmessage.py --strict
```

`--strict` also reports non-crashing shape problems (non-BIP44 depth, unhardened account, etc.). The default mode reports only paths that raise.

## What It Checks

1. `DecodeQR.add_data()` must not raise on malformed `signmessage` payloads.
2. `parse_derivation_path()` must return `clean_match=False` for malformed paths rather than raising.
3. If `parse_derivation_path()` returns `clean_match=True`, the exact operations used by the views must not raise:
   - `get_xpub(wallet_derivation_path)` in `SeedSignMessageConfirmAddressView`
   - `get_single_sig_address(...)` in `SeedSignMessageConfirmAddressView`
   - `sign_message(...)` in `SeedSignMessageSignedMessageQRView`

The checks mirror the view code. The cases below were also replayed through the real `Controller` flow and reached `UnhandledExceptionView` (except where noted).

## Baselines

On this branch's base (`dev` at `ebc1e11f`), the fuzzer also reports the pre-existing decoder/parser crashes that the signmessage hardening work addresses: `signmessage`, short paths such as `m`, and `m/48h/...`.

On the hardening head (`67d03370`), the decoder checks pass and the remaining findings are below. All paths use `signmessage <path> ascii:test`.

| Path                                        | Failure                                                                                                        |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `m/84h/0h/0h/0/2147483648`                  | `HDError: Can't do hardened with public key` at address derivation                                             |
| `m/84h/0h/0h/0/999999999999999999999999`    | `HDError: Index should be less then 2^32` at address derivation (and again at signing)                         |
| `m/84h/0h/invalid_acc/0/0`                  | `ValueError: invalid literal for int()` at xpub derivation                                                     |
| `m/84h/0h/999999999999999999999999h/0/0`    | `HDError: Index should be less then 2^32` at xpub derivation                                                   |
| `m/84h/0h/-1/0/0`                           | `OverflowError: can't convert negative int to unsigned` at xpub derivation                                     |
| `m/84h/0h//0/0`                             | `IndexError: string index out of range` at signing                                                             |
| `m/99h/0h/0h/0/0`                           | `clean_match=True` for a custom path; the Start view accepts it, then the Confirm Address view raises          |
| `m/84H/0h/0h/0/0`                           | same custom-path mismatch (`H` is not normalized)                                                              |
| `m/84h/0h/0h/0/²`                           | parser raises `ValueError` (caught by the Start view, so it shows "not yet implemented" instead of crashing) |

The `²` case matters because `str.isdigit()` accepts some Unicode characters that `int()` rejects. The index/account checks currently rely on `isdigit()` and on `int()` succeeding, so a path can be marked `clean_match=True` even though `embit` cannot derive it.

## Why These Are Not Handled by `clean_match`

`parse_derivation_path()` only validates that the parsed fields are not `None`. It does not validate:

- the BIP32 index range (`< 2^31` for a non-hardened index),
- that the account component is numeric and hardened,
- that each path component is a valid BIP32 component,
- that the path has exactly five components.

As a result, malformed paths reach the address/signing views and raise there.
