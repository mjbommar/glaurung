#!/usr/bin/env python3
"""Import selected Capstone MC vectors into Glaurung's structured corpus.

The importer deliberately stores semantic operands rather than Capstone's
presentation buffers. It currently accepts register/immediate-only families;
new operand forms must gain an explicit parser before their vectors can enter
the checked-in QA corpus.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
from typing import Any


DEFAULT_MNEMONICS = frozenset(
    {
        "add",
        "adds",
        "addp",
        "abs",
        "aesd",
        "aese",
        "aesimc",
        "aesmc",
        "adc",
        "adcs",
        "and",
        "ands",
        "adr",
        "adrp",
        "asr",
        "b",
        "bl",
        "bic",
        "bics",
        "bfi",
        "bfc",
        "bif",
        "bit",
        "bsl",
        "bfxil",
        "br",
        "blr",
        "cmn",
        "cmp",
        "cmeq",
        "cmge",
        "cmgt",
        "cmhi",
        "cmhs",
        "cmle",
        "cmlt",
        "cmtst",
        "cls",
        "clz",
        "crc32b",
        "crc32h",
        "crc32w",
        "crc32x",
        "crc32cb",
        "crc32ch",
        "crc32cw",
        "crc32cx",
        "clrex",
        "dc",
        "ccmn",
        "ccmp",
        "csel",
        "csinc",
        "csinv",
        "csneg",
        "cset",
        "csetm",
        "cinc",
        "cinv",
        "cneg",
        "eor",
        "eon",
        "fabs",
        "fabd",
        "facge",
        "facgt",
        "fadd",
        "faddp",
        "fccmp",
        "fccmpe",
        "fcmp",
        "fcmpe",
        "fcmeq",
        "fcmge",
        "fcmgt",
        "fcmle",
        "fcmlt",
        "fcsel",
        "fcvt",
        "fcvtas",
        "fcvtau",
        "fcvtms",
        "fcvtmu",
        "fcvtns",
        "fcvtnu",
        "fcvtxn",
        "fcvtps",
        "fcvtpu",
        "fcvtzs",
        "fcvtzu",
        "fdiv",
        "fmax",
        "fmaxnm",
        "fmin",
        "fminnm",
        "fmla",
        "fmls",
        "fmadd",
        "fmov",
        "fmsub",
        "fmul",
        "fmulx",
        "fneg",
        "fnmadd",
        "fnmsub",
        "fnmul",
        "frinta",
        "frecpe",
        "frecps",
        "frecpx",
        "frinti",
        "frintm",
        "frintn",
        "frintp",
        "frintx",
        "frintz",
        "frsqrte",
        "frsqrts",
        "fsqrt",
        "fsub",
        "scvtf",
        "ucvtf",
        "dmb",
        "drps",
        "dsb",
        "eret",
        "extr",
        "ext",
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsb",
        "ldrsh",
        "ldrsw",
        "ldur",
        "ldurb",
        "ldurh",
        "ldursb",
        "ldursh",
        "ldursw",
        "ldnp",
        "ldp",
        "ldar",
        "ldarb",
        "ldarh",
        "ldaxp",
        "ldaxr",
        "ldaxrb",
        "ldaxrh",
        "ldxp",
        "ldxr",
        "ldxrb",
        "ldxrh",
        "ldpsw",
        "lsl",
        "lsr",
        "mov",
        "mvn",
        "ngc",
        "ngcs",
        "neg",
        "movk",
        "movn",
        "movz",
        "mrs",
        "msr",
        "nop",
        "madd",
        "mla",
        "mls",
        "mneg",
        "msub",
        "mul",
        "orr",
        "orn",
        "prfm",
        "prfum",
        "ret",
        "rbit",
        "rev",
        "rev16",
        "rev32",
        "ror",
        "str",
        "strb",
        "strh",
        "sttr",
        "sttrb",
        "sttrh",
        "stur",
        "sturb",
        "sturh",
        "ldtr",
        "ldtrb",
        "ldtrh",
        "ldtrsb",
        "ldtrsh",
        "ldtrsw",
        "stnp",
        "stp",
        "stlr",
        "stlrb",
        "stlrh",
        "stlxp",
        "stlxr",
        "stlxrb",
        "stlxrh",
        "stxp",
        "stxr",
        "stxrb",
        "stxrh",
        "sub",
        "subs",
        "hint",
        "hlt",
        "hvc",
        "ic",
        "isb",
        "sev",
        "sevl",
        "smc",
        "svc",
        "sys",
        "sysl",
        "tlbi",
        "at",
        "smaddl",
        "smnegl",
        "smsubl",
        "smulh",
        "smull",
        "sbc",
        "sbcs",
        "sha1c",
        "sha1h",
        "sha1m",
        "sha1p",
        "sha1su0",
        "sha1su1",
        "sha256h",
        "sha256h2",
        "sha256su0",
        "sha256su1",
        "sdiv",
        "sqabs",
        "sqadd",
        "sqdmlal",
        "sqdmlsl",
        "sqdmulh",
        "sqdmull",
        "sqrdmulh",
        "sqrshrn",
        "sqrshrun",
        "sqneg",
        "sqshlu",
        "sqshrun",
        "sqshrn",
        "sqrshl",
        "sqshl",
        "sqxtn",
        "sqxtun",
        "sqsub",
        "sshl",
        "sshr",
        "sshll",
        "sshll2",
        "ssra",
        "srsra",
        "srshr",
        "shl",
        "sli",
        "sri",
        "srshl",
        "srhadd",
        "suqadd",
        "sbfiz",
        "sbfx",
        "tst",
        "tbl",
        "tbx",
        "umaddl",
        "umnegl",
        "umsubl",
        "umulh",
        "umull",
        "udiv",
        "uqadd",
        "uqrshl",
        "uqshl",
        "uqxtn",
        "uqsub",
        "urshl",
        "urhadd",
        "usqadd",
        "ushl",
        "ushr",
        "ushll",
        "ushll2",
        "usra",
        "ursra",
        "urshr",
        "uqshl",
        "uqshrn",
        "uqrshrn",
        "ubfiz",
        "ubfx",
        "sxtb",
        "sxth",
        "sxtw",
        "uxtb",
        "uxth",
        "wfe",
        "wfi",
        "yield",
        "brk",
        "dcps1",
        "dcps2",
        "dcps3",
        "cbz",
        "cbnz",
    }
    | {
        f"b.{condition}"
        for condition in (
            "eq",
            "ne",
            "hs",
            "lo",
            "mi",
            "pl",
            "vs",
            "vc",
            "hi",
            "ls",
            "ge",
            "lt",
            "gt",
            "le",
        )
    }
)


def parse_operand(text: str) -> dict[str, Any]:
    """Parse a register or immediate operand without guessing other forms."""
    if text.startswith("{") and text.endswith("}"):
        members = [parse_operand(member.strip()) for member in text[1:-1].split(",")]
        if not members or any(
            set(member) != {"register", "vector_shape"} for member in members
        ):
            raise ValueError(f"unsupported register-list operand syntax: {text!r}")
        shape = members[0]["vector_shape"]
        if any(member["vector_shape"] != shape for member in members[1:]):
            raise ValueError(f"mixed register-list arrangements: {text!r}")
        return {
            "register_list": [member["register"] for member in members],
            "vector_shape": shape,
        }
    if text.startswith("#"):
        if text == "#0.0":
            return {"immediate": 0}
        if "." in text:
            return {"floating": float(text[1:])}
        return {"immediate": int(text[1:], 0)}
    if text.startswith("[") and text.endswith("]"):
        fields = [field.strip() for field in text[1:-1].split(",")]
        aliases = {"x29": "fp", "x30": "lr"}
        memory: dict[str, str | int] = {"base": aliases.get(fields[0], fields[0])}
        if len(fields) == 2 and fields[1].startswith("#"):
            memory["displacement"] = int(fields[1][1:], 0)
        elif len(fields) >= 2:
            memory["index"] = aliases.get(fields[1], fields[1])
            if len(fields) == 3:
                modifier_fields = fields[2].split()
                memory["modifier"] = modifier_fields[0]
                if len(modifier_fields) == 2:
                    memory["shift"] = int(modifier_fields[1][1:], 0)
            elif len(fields) != 2:
                raise ValueError(f"unsupported memory operand syntax: {text!r}")
        elif len(fields) != 1:
            raise ValueError(f"unsupported memory operand syntax: {text!r}")
        return {"memory": memory}
    if text.startswith("v") and "." in text and text.endswith("]"):
        register, lane = text.split(".", 1)
        element, separator, index_text = lane[:-1].partition("[")
        element_bits = {"b": 8, "h": 16, "s": 32, "d": 64}.get(element)
        if register[1:].isdigit() and separator and element_bits is not None:
            return {
                "register": register,
                "vector_shape": {"lanes": 1, "element_bits": element_bits},
                "vector_index": int(index_text, 0),
            }
    if text.startswith("v") and "." in text:
        register, arrangement = text.split(".", 1)
        element_bits = {"b": 8, "h": 16, "s": 32, "d": 64, "q": 128}.get(
            arrangement[-1:]
        )
        lanes = arrangement[:-1]
        if register[1:].isdigit() and lanes.isdigit() and element_bits is not None:
            return {
                "register": register,
                "vector_shape": {
                    "lanes": int(lanes),
                    "element_bits": element_bits,
                },
            }
    if text and all(character.isalnum() or character in "._" for character in text):
        # Glaurung's current Capstone adapter uses cs_reg_name(), which
        # canonicalizes architectural X30 to the semantic alias LR.
        aliases = {"x29": "fp", "x30": "lr"}
        return {"register": aliases.get(text, text)}
    raise ValueError(f"unsupported operand syntax: {text!r}")


def parse_operands(text: str) -> list[dict[str, Any]]:
    """Parse operands and fold immediate shifts into their semantic value."""
    if not text:
        return []
    parts: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(text):
        depth += character in "[{"
        depth -= character in "]}"
        if character == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    pre_index = False
    for index, part in enumerate(parts):
        if part.endswith("]!"):
            parts[index] = part[:-1]
            pre_index = True
    shift = 0
    register_modifier: tuple[str, int] | None = None
    modifier_fields = parts[-1].split()
    register_modifiers = {
        "uxtb",
        "uxth",
        "uxtw",
        "uxtx",
        "sxtb",
        "sxth",
        "sxtw",
        "sxtx",
    }
    if (
        modifier_fields
        and modifier_fields[0] in register_modifiers | {"lsl", "lsr", "asr", "ror"}
        and len(parts) >= 2
        and not parts[-2].startswith("#")
    ):
        modifier = parts.pop()
        modifier_fields = modifier.split()
        modifier_shift = (
            int(modifier_fields[1][1:], 0) if len(modifier_fields) == 2 else 0
        )
        register_modifier = (modifier_fields[0], modifier_shift)
    elif parts[-1].startswith("lsl #"):
        shift = int(parts.pop()[5:], 0)
    operands = [parse_operand(item) for item in parts]
    for operand in operands:
        floating = operand.pop("floating", None)
        if floating is None:
            continue
        destination = operands[0].get("register")
        if not isinstance(destination, str) or destination[:1] not in {"s", "d"}:
            raise ValueError("floating immediate requires an S or D destination")
        packed = struct.pack("<f" if destination.startswith("s") else "<d", floating)
        bits = int.from_bytes(packed, "little")
        if bits >= 1 << 63:
            bits -= 1 << 64
        operand["immediate"] = bits
    if pre_index:
        memory = next(
            (operand["memory"] for operand in operands if "memory" in operand), None
        )
        if not isinstance(memory, dict):
            raise ValueError("pre-index marker requires a memory operand")
        displacement = memory.get("displacement", 0)
        if displacement:
            operands.append({"immediate": displacement})
    if register_modifier is not None:
        if "register" not in operands[-1]:
            raise ValueError("register modifier must follow a register")
        operands[-1]["modifier"], operands[-1]["shift"] = register_modifier
    if shift:
        immediate = operands[-1].get("immediate")
        if not isinstance(immediate, int):
            raise ValueError("immediate LSL modifier must follow an immediate")
        operands[-1] = {"immediate": immediate << shift}
    return operands


def selected_encoding(mnemonic: str, encoded_bytes: list[int]) -> bool:
    """Restrict broad mnemonics to encoding families implemented natively."""
    load_store = {
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsb",
        "ldrsh",
        "ldrsw",
        "str",
        "strb",
        "strh",
    }
    unscaled_load_store = {
        "ldur",
        "ldurb",
        "ldurh",
        "ldursb",
        "ldursh",
        "ldursw",
        "stur",
        "sturb",
        "sturh",
    }
    word = int.from_bytes(encoded_bytes, "little")
    if mnemonic in {"tbl", "tbx"}:
        return word & 0xBFE0_9C00 in {0x0E00_0000, 0x0E00_1000}
    if mnemonic in {"and", "bic", "orr", "orn", "eor", "bsl", "bit", "bif", "mov"}:
        if word & 0xBFE0_FC00 in {
            0x0E20_1C00,
            0x0E60_1C00,
            0x0EA0_1C00,
            0x0EE0_1C00,
            0x2E20_1C00,
            0x2E60_1C00,
            0x2EA0_1C00,
            0x2EE0_1C00,
        }:
            return True
    if mnemonic in {
        "aese",
        "aesd",
        "aesmc",
        "aesimc",
        "sha1h",
        "sha1su1",
        "sha256su0",
    }:
        return word & 0xFFFF_FC00 in {
            0x4E28_4800,
            0x4E28_5800,
            0x4E28_6800,
            0x4E28_7800,
            0x5E28_0800,
            0x5E28_1800,
            0x5E28_2800,
        }
    if mnemonic in {"sha1c", "sha1p", "sha1m", "sha1su0", "sha256h", "sha256h2", "sha256su1"}:
        return word & 0xFFE0_FC00 in {
            0x5E00_0000,
            0x5E00_1000,
            0x5E00_2000,
            0x5E00_3000,
            0x5E00_4000,
            0x5E00_5000,
            0x5E00_6000,
        }
    if mnemonic in {"add", "sub"} and word & 0xDF20_FC00 == 0x5E20_8400:
        return True
    if mnemonic in {"add", "sub"} and word & 0xBF20_FC00 in {
        0x0E20_8400,
        0x2E20_8400,
    }:
        return True
    if mnemonic == "addp":
        return word & 0xFF3F_FC00 == 0x5E31_B800 or word & 0xBF20_FC00 == 0x0E20_BC00
    if mnemonic == "faddp":
        return word & 0xFF3F_FC00 == 0x7E30_D800 or word & 0xBF20_FC00 == 0x2E20_D400
    if mnemonic in {"sshl", "ushl"}:
        return word & 0xDF20_FC00 == 0x5E20_4400
    if mnemonic in {"srhadd", "urhadd"}:
        return word & 0xBF20_FC00 in {0x0E20_1400, 0x2E20_1400}
    if mnemonic in {"sqadd", "uqadd"}:
        return word & 0xDF20_FC00 == 0x5E20_0C00
    if mnemonic in {"sqsub", "uqsub"}:
        return word & 0xDF20_FC00 == 0x5E20_2C00
    if mnemonic in {"sqshl", "uqshl"}:
        return (
            word & 0xDF20_FC00 == 0x5E20_4C00
            or word & 0xDF80_0400 == 0x5F00_0400
            or word & 0xBF20_FC00 in {0x0E20_4C00, 0x2E20_4C00}
        )
    if mnemonic in {"sqrshl", "uqrshl"}:
        return word & 0xDF20_FC00 == 0x5E20_5C00 or word & 0xBF20_FC00 in {
            0x0E20_5C00,
            0x2E20_5C00,
        }
    if mnemonic in {"srshl", "urshl"}:
        return word & 0xDF20_FC00 == 0x5E20_5400 or word & 0xBF20_FC00 in {
            0x0E20_5400,
            0x2E20_5400,
        }
    if mnemonic in {"suqadd", "usqadd"}:
        return word & 0xDF3F_FC00 == 0x5E20_3800
    if mnemonic == "sqxtun":
        return word & 0xDF3F_FC00 == 0x5E21_2800
    if mnemonic in {"sqxtn", "uqxtn"}:
        return word & 0xDF3F_FC00 == 0x5E21_4800
    if mnemonic in {"cmeq", "cmtst"} and word & 0xDF20_FC00 == 0x5E20_8C00:
        return True
    if mnemonic in {"cmge", "cmhs"} and word & 0xDF20_FC00 == 0x5E20_3C00:
        return True
    if mnemonic in {"cmgt", "cmhi"} and word & 0xDF20_FC00 == 0x5E20_3400:
        return True
    if mnemonic in {"cmeq", "cmle"} and word & 0xDF3F_FC00 == 0x5E20_9800:
        return True
    if mnemonic in {"cmge", "cmgt"} and word & 0xDF3F_FC00 == 0x5E20_8800:
        return True
    if mnemonic == "cmlt":
        return word & 0xDF3F_FC00 == 0x5E20_A800
    if mnemonic in {"abs", "neg"}:
        return word & 0xDF3F_FC00 == 0x5E20_B800
    if mnemonic in {"sqabs", "sqneg"}:
        return word & 0xDF3F_FC00 == 0x5E20_7800
    if mnemonic == "fabd":
        return word & 0xFF20_FC00 == 0x7E20_D400
    if mnemonic in {"fcmeq", "fcmge", "fcmgt"}:
        return word & 0xDF20_FC00 == 0x5E20_E400 or word & 0xDF3F_FC00 in {
            0x5E20_C800,
            0x5E20_D800,
            0x5E20_E800,
        }
    if mnemonic in {"facge", "facgt"}:
        return word & 0xDF20_FC00 == 0x5E20_EC00 or word & 0xBF20_FC00 == 0x2E20_EC00
    if mnemonic in {"fcmle", "fcmlt"}:
        return word & 0xDF3F_FC00 in {0x5E20_C800, 0x5E20_D800, 0x5E20_E800}
    if mnemonic in {"frecps", "frsqrts"}:
        return word & 0xDFA0_FC00 in {0x5E20_FC00, 0x5EA0_FC00} or word & 0xBF80_FC00 in {
            0x0E00_FC00,
            0x0E80_FC00,
        }
    if mnemonic in {"frecpe", "frsqrte"}:
        return word & 0xDF3F_FC00 == 0x5E21_D800
    if mnemonic == "frecpx":
        return word & 0xDF3F_FC00 == 0x5E21_F800
    if mnemonic in {"sqdmulh", "sqrdmulh"}:
        return word & 0xDF20_FC00 == 0x5E20_B400 or word & 0xFF00_F400 in {
            0x5F00_C000,
            0x5F00_D000,
        }
    if mnemonic == "fmulx":
        return word & 0xFF20_FC00 == 0x5E20_DC00 or word & 0xDF00_F400 == 0x5F00_9000
    if mnemonic == "fmul" and word & 0xDF00_F400 == 0x5F00_9000:
        return True
    if mnemonic in {"fmla", "fmls"}:
        return word & 0xFF00_F400 in {0x5F00_1000, 0x5F00_5000} or word & 0xBFA0_FC00 in {
            0x0E20_CC00,
            0x0EA0_CC00,
        }
    if mnemonic in {"mla", "mls"}:
        return word & 0xBF20_FC00 in {0x0E20_9400, 0x2E20_9400}
    if mnemonic in {"sqdmlal", "sqdmlsl", "sqdmull"}:
        return word & 0xFF20_FC00 in {
            0x5E20_9000,
            0x5E20_B000,
            0x5E20_D000,
        } or word & 0xFF00_F400 in {0x5F00_3000, 0x5F00_7000, 0x5F00_B000}
    if mnemonic == "ext":
        return word & 0xBFE0_8400 == 0x2E00_0000
    if mnemonic in {
        "sshr",
        "ushr",
        "ssra",
        "usra",
        "srshr",
        "urshr",
        "srsra",
        "ursra",
        "shl",
        "sri",
        "sli",
        "sqshl",
        "uqshl",
        "sqshlu",
        "sqshrn",
        "uqshrn",
        "sqrshrn",
        "uqrshrn",
        "sqshrun",
        "sqrshrun",
    }:
        return word & 0xDF80_0400 == 0x5F00_0400
    if mnemonic in {"sshll", "sshll2", "ushll", "ushll2"}:
        return word & 0x9F80_FC00 == 0x0F00_A400
    if mnemonic == "mrs":
        return word & 0xFFF0_0000 == 0xD530_0000
    if mnemonic == "msr":
        return word & 0xFFF0_0000 == 0xD510_0000 or (word & 0xFFF8_F01F == 0xD500_401F)
    if mnemonic in {"svc", "hvc", "smc", "brk", "hlt", "dcps1", "dcps2", "dcps3"}:
        return word & 0xFFE0_001F in {
            0xD400_0001,
            0xD400_0002,
            0xD400_0003,
            0xD420_0000,
            0xD440_0000,
            0xD4A0_0001,
            0xD4A0_0002,
            0xD4A0_0003,
        }
    if mnemonic in {"nop", "hint", "yield", "wfe", "wfi", "sev", "sevl"}:
        return word & 0xFFFF_F01F == 0xD503_201F
    if mnemonic in {"clrex", "dsb", "dmb", "isb"}:
        return word & 0xFFFF_F0FF in {
            0xD503_305F,
            0xD503_309F,
            0xD503_30BF,
            0xD503_30DF,
        }
    if mnemonic in {"eret", "drps"}:
        return word in {0xD69F_03E0, 0xD6BF_03E0}
    if mnemonic in {"at", "dc", "ic", "tlbi", "sys"}:
        return word & 0xFFF8_0000 == 0xD508_0000
    if mnemonic == "sysl":
        return word & 0xFFF8_0000 == 0xD528_0000
    if mnemonic in {
        "fmov",
        "fabs",
        "fneg",
        "fsqrt",
        "fcvt",
        "frintn",
        "frintp",
        "frintm",
        "frintz",
        "frinta",
        "frintx",
        "frinti",
    }:
        if mnemonic == "fmov":
            return (
                (word & 0xFF20_7C00 == 0x1E20_4000 and (word >> 15) & 0x3F == 0)
                or (word & 0x5F20_FC00 == 0x1E20_0000 and (word >> 16) & 0x1F in {6, 7})
                or word & 0xFF20_1FE0 == 0x1E20_1000
                or word & 0xFFFE_FC00 == 0x9EAE_0000
            )
        return word & 0xFF20_7C00 == 0x1E20_4000
    if mnemonic in {
        "fmul",
        "fdiv",
        "fadd",
        "fsub",
        "fmax",
        "fmin",
        "fmaxnm",
        "fminnm",
        "fnmul",
    }:
        return word & 0xFF20_0C00 == 0x1E20_0800 or (
            mnemonic in {"fadd", "fsub"}
            and word & 0xBFA0_FC00 in {0x0E20_D400, 0x0EA0_D400}
        )
    if mnemonic in {"fmadd", "fmsub", "fnmadd", "fnmsub"}:
        return word & 0xFF00_0000 == 0x1F00_0000
    if mnemonic in {"fcmp", "fcmpe"}:
        return word & 0xFF20_FC07 == 0x1E20_2000
    if mnemonic in {"fccmp", "fccmpe"}:
        return word & 0xFF20_0C00 == 0x1E20_0400
    if mnemonic == "fcsel":
        return word & 0xFF20_0C00 == 0x1E20_0C00
    if (
        mnemonic
        in {
            "fcvtzs",
            "fcvtzu",
            "scvtf",
            "ucvtf",
        }
        and word & 0x5F20_0000 == 0x1E00_0000
    ):
        return (word >> 16) & 0x1F in {2, 3, 24, 25}
    if mnemonic in {
        "fcvtns",
        "fcvtnu",
        "fcvtps",
        "fcvtpu",
        "fcvtms",
        "fcvtmu",
        "fcvtzs",
        "fcvtzu",
        "scvtf",
        "ucvtf",
        "fcvtas",
        "fcvtau",
    }:
        return (
            word & 0x5F20_FC00 == 0x1E20_0000
            and (word >> 16) & 0x1F in {
                0,
                1,
                2,
                3,
                4,
                5,
                8,
                9,
                16,
                17,
                24,
                25,
            }
        ) or word & 0xDFBF_FC00 in {
            0x5E21_A800,
            0x5EA1_A800,
            0x5E21_B800,
            0x5EA1_B800,
            0x5E21_C800,
            0x5E21_D800,
        } or (
            mnemonic in {"scvtf", "ucvtf", "fcvtzs", "fcvtzu"}
            and word & 0xDF80_FC00 in {0x5F00_E400, 0x5F00_FC00}
        )
    if mnemonic == "fcvtxn":
        return word & 0xFFFF_FC00 == 0x7E61_6800
    if mnemonic == "prfm":
        return word & 0xFFC0_0000 == 0xF980_0000 or (word & 0xFFE0_0C00 == 0xF8A0_0800)
    if mnemonic == "prfum":
        return word & 0xFFE0_0C00 == 0xF880_0000
    if mnemonic in load_store:
        return (
            word & 0x3F00_0000 in {0x3900_0000, 0x3D00_0000}
            or (word & 0x3F20_0000 == 0x3800_0000 and (word >> 10) & 0x3 in {1, 3})
            or (word & 0x3F20_0C00 == 0x3820_0800)
            or (word & 0x3F20_0000 == 0x3C00_0000 and (word >> 10) & 0x3 in {1, 3})
            or (word & 0x3F20_0C00 == 0x3C20_0800)
            or (mnemonic == "ldr" and word & 0x3B00_0000 == 0x1800_0000)
        )
    if mnemonic in {
        "sttr",
        "sttrb",
        "sttrh",
        "ldtr",
        "ldtrb",
        "ldtrh",
        "ldtrsb",
        "ldtrsh",
        "ldtrsw",
    }:
        return word & 0x3F20_0C00 == 0x3800_0800
    if mnemonic in unscaled_load_store:
        return word & 0x3F20_0C00 in {0x3800_0000, 0x3C00_0000}
    if mnemonic in {"ldp", "stp", "ldnp", "stnp", "ldpsw"}:
        return word & 0x3A00_0000 == 0x2800_0000
    if mnemonic in {
        "stxrb",
        "stxrh",
        "stxr",
        "ldxrb",
        "ldxrh",
        "ldxr",
        "stxp",
        "ldxp",
        "stlxrb",
        "stlxrh",
        "stlxr",
        "ldaxrb",
        "ldaxrh",
        "ldaxr",
        "stlxp",
        "ldaxp",
        "stlrb",
        "stlrh",
        "stlr",
        "ldarb",
        "ldarh",
        "ldar",
    }:
        return word & 0x3F00_0000 == 0x0800_0000
    if mnemonic in {"mov", "mvn", "movk", "movn", "movz"}:
        return (
            word & 0x1F80_0000 in {0x1200_0000, 0x1280_0000}
            or (word & 0x1F00_0000 == 0x0A00_0000)
            or (
                mnemonic == "mov"
                and word & 0x1F00_0000 == 0x1100_0000
                and word & 0x60C0_0000 == 0
                and (word & 0x1F == 31 or (word >> 5) & 0x1F == 31)
            )
            or (mnemonic == "mov" and word & 0xFFE0_FC00 == 0x5E00_0400)
        )
    if mnemonic in {"and", "ands", "orr", "eor", "bic", "bics", "orn", "eon", "tst"}:
        return word & 0x1F80_0000 == 0x1200_0000 or (word & 0x1F00_0000 == 0x0A00_0000)
    if mnemonic not in {"add", "adds", "sub", "subs", "cmp", "cmn"}:
        if mnemonic in {"adc", "adcs", "sbc", "sbcs", "ngc", "ngcs"}:
            return word & 0x1FE0_FC00 == 0x1A00_0000
        if mnemonic in {
            "csel",
            "csinc",
            "csinv",
            "csneg",
            "cset",
            "csetm",
            "cinc",
            "cinv",
            "cneg",
        }:
            return word & 0x3FE0_0800 == 0x1A80_0000
        if mnemonic in {"ccmp", "ccmn"}:
            return word & 0x3FE0_0410 == 0x3A40_0000
        if mnemonic in {
            "asr",
            "bfi",
            "bfxil",
            "lsl",
            "lsr",
            "sbfiz",
            "sbfx",
            "sxtb",
            "sxth",
            "sxtw",
            "ubfiz",
            "ubfx",
            "uxtb",
            "uxth",
        }:
            return word & 0x1F80_0000 == 0x1300_0000 or (
                mnemonic in {"asr", "lsl", "lsr"}
                and word & 0x7FE0_FC00 in {0x1AC0_2000, 0x1AC0_2400, 0x1AC0_2800}
            )
        if mnemonic == "bfc":
            return word & 0x1F80_0000 == 0x1300_0000
        if mnemonic.startswith("crc32"):
            return word & 0x7FE0_E000 == 0x1AC0_4000
        if mnemonic == "ror":
            return word & 0x7FE0_FC00 == 0x1AC0_2C00 or (
                word & 0x1F80_0000 == 0x1380_0000
            )
        if mnemonic in {"udiv", "sdiv"}:
            return word & 0x7FE0_FC00 in {0x1AC0_0800, 0x1AC0_0C00}
        if mnemonic in {"rbit", "rev", "rev16", "rev32", "clz", "cls"}:
            return word & 0x7FFF_0000 == 0x5AC0_0000
        if mnemonic == "extr":
            return word & 0x1F80_0000 == 0x1380_0000
        if mnemonic in {"madd", "mneg", "msub", "mul"}:
            return word & 0x7FE0_0000 == 0x1B00_0000
        if mnemonic in {
            "smaddl",
            "smnegl",
            "smsubl",
            "smull",
            "umaddl",
            "umnegl",
            "umsubl",
            "umull",
        }:
            return word & 0xFF60_0000 == 0x9B20_0000
        if mnemonic in {"smulh", "umulh"}:
            return word & 0xFF60_FC00 == 0x9B40_7C00
        return True
    return (
        word & 0x1F00_0000 == 0x1100_0000
        or word & 0x1FE0_0000 == 0x0B20_0000
        or word & 0x1F20_0000 == 0x0B00_0000
    )


def parse_mc_file(path: Path, mnemonics: frozenset[str]) -> list[dict[str, Any]]:
    """Read selected vectors from one Capstone ``suite/MC`` file."""
    vectors: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(path.read_text().splitlines(), 1):
        if " = " not in raw_line or raw_line.lstrip().startswith(("#", "//")):
            continue
        encoded, assembly = raw_line.split(" = ", 1)
        mnemonic, separator, operand_text = assembly.strip().partition(" ")
        if mnemonic not in mnemonics:
            continue
        try:
            encoded_bytes = [int(item, 0) for item in encoded.split(",")]
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: invalid byte sequence") from error
        if len(encoded_bytes) != 4 or any(
            not 0 <= item <= 255 for item in encoded_bytes
        ):
            raise ValueError(f"{path}:{line_number}: expected one A64 instruction")
        if not selected_encoding(mnemonic, encoded_bytes):
            continue
        operands = parse_operands(operand_text if separator else "")
        if mnemonic in {
            "csel",
            "csinc",
            "csinv",
            "csneg",
            "cset",
            "csetm",
            "cinc",
            "cinv",
            "cneg",
            "ccmp",
            "ccmn",
            "fccmp",
            "fccmpe",
            "fcsel",
        }:
            condition = operands.pop()
            if condition.get("register") not in {
                "eq",
                "ne",
                "hs",
                "lo",
                "mi",
                "pl",
                "vs",
                "vc",
                "hi",
                "ls",
                "ge",
                "lt",
                "gt",
                "le",
                "al",
                "nv",
            }:
                raise ValueError(f"invalid condition operand at {path}:{line_number}")
        word = int.from_bytes(encoded_bytes, "little")
        if word & 0x9F80_0000 == 0x9200_0000:
            for operand in operands:
                immediate = operand.get("immediate")
                if isinstance(immediate, int) and immediate > (1 << 63) - 1:
                    operand["immediate"] = immediate - (1 << 64)
        vectors.append(
            {
                "line": line_number,
                "bytes": encoded_bytes,
                "mnemonic": mnemonic,
                "operands": operands,
            }
        )
    return vectors


def active_a64_lines(path: Path) -> dict[int, str]:
    """Return every active four-byte vector in the pinned basic A64 MC file."""
    active: dict[int, str] = {}
    for line_number, raw_line in enumerate(path.read_text().splitlines(), 1):
        if " = " not in raw_line or raw_line.lstrip().startswith(("#", "//")):
            continue
        encoded, _ = raw_line.split(" = ", 1)
        try:
            encoded_bytes = [int(item, 0) for item in encoded.split(",")]
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: invalid byte sequence") from error
        if len(encoded_bytes) == 4 and all(0 <= item <= 255 for item in encoded_bytes):
            active[line_number] = raw_line.strip()
    return active


def document(source: Path) -> dict[str, Any]:
    """Build the stable v1 corpus document for the current AArch64 slice."""
    vectors = parse_mc_file(source, DEFAULT_MNEMONICS)
    active = active_a64_lines(source)
    imported_lines = {vector["line"] for vector in vectors}
    if imported_lines != active.keys():
        missing = sorted(active.keys() - imported_lines)
        unexpected = sorted(imported_lines - active.keys())
        details = [
            *(f"missing {source}:{line}: {active[line]}" for line in missing[:20]),
            *(f"unexpected imported line {source}:{line}" for line in unexpected[:20]),
        ]
        raise ValueError(
            "basic A64 corpus import is incomplete "
            f"({len(vectors)} imported, {len(active)} active); " + "; ".join(details)
        )

    def family_order(vector: dict[str, Any]) -> tuple[int, int]:
        mnemonic = vector["mnemonic"]
        if mnemonic in {"cbz", "cbnz"} or mnemonic.startswith("b."):
            family = 0
        elif mnemonic in {"adr", "adrp"}:
            family = 1
        elif mnemonic in {"b", "bl", "br", "blr", "ret"}:
            family = 2
        elif mnemonic in {
            "add",
            "adds",
            "sub",
            "subs",
            "cmp",
            "cmn",
            "adc",
            "adcs",
            "sbc",
            "sbcs",
            "ngc",
            "ngcs",
            "ccmp",
            "ccmn",
        }:
            family = 3
        elif mnemonic in {
            "madd",
            "mneg",
            "msub",
            "mul",
            "smaddl",
            "smnegl",
            "smsubl",
            "smulh",
            "smull",
            "umaddl",
            "umnegl",
            "umsubl",
            "umulh",
            "umull",
        }:
            family = 4
        elif mnemonic in {
            "asr",
            "bfi",
            "bfxil",
            "lsl",
            "lsr",
            "sbfiz",
            "sbfx",
            "sxtb",
            "sxth",
            "sxtw",
            "ubfiz",
            "ubfx",
            "uxtb",
            "uxth",
            "cls",
            "clz",
            "extr",
            "rbit",
            "rev",
            "rev16",
            "rev32",
            "ror",
            "sdiv",
            "udiv",
        }:
            family = 5
        elif mnemonic in {
            "csel",
            "csinc",
            "csinv",
            "csneg",
            "cset",
            "csetm",
            "cinc",
            "cinv",
            "cneg",
        }:
            family = 6
        elif mnemonic in {"mov", "mvn", "movk", "movn", "movz"}:
            family = 7
        elif mnemonic in {
            "and",
            "ands",
            "orr",
            "eor",
            "bic",
            "bics",
            "orn",
            "eon",
            "tst",
        }:
            family = 8
        elif mnemonic in {"ldp", "stp", "ldnp", "stnp", "ldpsw"}:
            family = 9
        elif mnemonic in {
            "svc",
            "hvc",
            "smc",
            "brk",
            "hlt",
            "dcps1",
            "dcps2",
            "dcps3",
            "nop",
            "hint",
            "yield",
            "wfe",
            "wfi",
            "sev",
            "sevl",
            "clrex",
            "dsb",
            "dmb",
            "isb",
            "eret",
            "drps",
            "mrs",
            "msr",
            "at",
            "dc",
            "ic",
            "tlbi",
            "sys",
            "sysl",
        }:
            family = 10
        else:
            family = 11
        return family, vector["line"]

    vectors.sort(key=family_order)
    return {
        "schema": "glaurung-capstone-mc-v1",
        "upstream": {
            "project": "capstone",
            "version": "5.0.0",
            "crate": "capstone-sys 0.16.0",
            "path": f"suite/MC/AArch64/{source.name}",
            "licenses": ["BSD-3-Clause", "NCSA"],
        },
        "vectors": vectors,
    }


def rust_sysreg_table(sources: list[Path]) -> str:
    """Generate a packed bidirectional system-register name index."""
    directions: dict[int, dict[str, str]] = {}
    for source in sources:
        for vector in parse_mc_file(source, frozenset({"mrs", "msr"})):
            word = int.from_bytes(vector["bytes"], "little")
            operands = vector["operands"]
            if vector["mnemonic"] == "msr" and "immediate" in operands[-1]:
                continue
            name_operand = operands[1] if vector["mnemonic"] == "mrs" else operands[0]
            name = name_operand["register"]
            # Architecturally allocated but unnamed encodings have a lossless
            # algorithmic spelling and do not need table storage.
            if name.startswith("s") and "_c" in name:
                continue
            encoding = (word >> 5) & 0xFFFF
            pair = directions.setdefault(encoding, {})
            previous = pair.get(vector["mnemonic"])
            if previous is not None and previous != name:
                raise ValueError(
                    f"conflicting {vector['mnemonic']} names for system register "
                    f"0x{encoding:04x}: {previous!r} and {name!r}"
                )
            pair[vector["mnemonic"]] = name

    aliases: list[tuple[int, str, str, bool]] = []
    for source in sources:
        for vector in parse_mc_file(source, frozenset({"at", "dc", "ic", "tlbi"})):
            word = int.from_bytes(vector["bytes"], "little")
            operation = vector["operands"][0]["register"]
            aliases.append(
                (
                    (word >> 5) & 0x7FFF,
                    vector["mnemonic"],
                    operation,
                    len(vector["operands"]) == 2,
                )
            )

    names = sorted(
        {name for pair in directions.values() for name in pair.values()}
        | {operation for _, _, operation, _ in aliases}
    )
    offsets: dict[str, tuple[int, int]] = {}
    pool = ""
    for name in names:
        offsets[name] = (len(pool), len(name))
        pool += name

    lines = [
        "//! Generated by `tools/import_capstone_mc.py`; do not edit by hand.",
        "//! Names derive from the pinned Capstone/LLVM MC corpus under its",
        "//! BSD-3-Clause and NCSA notices in `tests/corpora/capstone/NOTICE.md`.",
        "",
        "const MISSING: u16 = u16::MAX;",
        f"const NAMES: &str = {json.dumps(pool)};",
        "",
        "#[derive(Clone, Copy)]",
        "#[repr(C)]",
        "struct Entry {",
        "    encoding: u16,",
        "    read_offset: u16,",
        "    write_offset: u16,",
        "    read_len: u8,",
        "    write_len: u8,",
        "}",
        "",
        f"const ENTRIES: [Entry; {len(directions)}] = [",
    ]
    for encoding, pair in sorted(directions.items()):
        read_offset, read_len = offsets.get(pair.get("mrs", ""), (0xFFFF, 0))
        write_offset, write_len = offsets.get(pair.get("msr", ""), (0xFFFF, 0))
        lines.append(
            "    Entry {\n"
            f"        encoding: 0x{encoding:04x},\n"
            f"        read_offset: 0x{read_offset:04x},\n"
            f"        write_offset: 0x{write_offset:04x},\n"
            f"        read_len: {read_len},\n"
            f"        write_len: {write_len},\n"
            "    },"
        )
    lines.extend(
        [
            "];",
            "",
            "#[derive(Clone, Copy)]",
            "#[repr(C)]",
            "struct AliasEntry {",
            "    encoding: u16,",
            "    name_offset: u16,",
            "    name_len: u8,",
            "    mnemonic: u8,",
            "    has_register: u8,",
            "}",
            "",
            f"const ALIASES: [AliasEntry; {len(aliases)}] = [",
        ]
    )
    mnemonic_ids = {"at": 0, "dc": 1, "ic": 2, "tlbi": 3}
    for encoding, mnemonic, operation, has_register in sorted(aliases):
        offset, length = offsets[operation]
        lines.append(
            "    AliasEntry {\n"
            f"        encoding: 0x{encoding:04x},\n"
            f"        name_offset: 0x{offset:04x},\n"
            f"        name_len: {length},\n"
            f"        mnemonic: {mnemonic_ids[mnemonic]},\n"
            f"        has_register: {int(has_register)},\n"
            "    },"
        )
    lines.extend(
        [
            "];",
            "",
            "/// Return the architectural name for an encoded readable or writable system register.",
            "pub fn lookup(encoding: u16, read: bool) -> Option<&'static str> {",
            "    let index = ENTRIES",
            "        .binary_search_by_key(&encoding, |entry| entry.encoding)",
            "        .ok()?;",
            "    let entry = ENTRIES[index];",
            "    let (offset, len) = if read {",
            "        (entry.read_offset, entry.read_len)",
            "    } else {",
            "        (entry.write_offset, entry.write_len)",
            "    };",
            "    if offset == MISSING {",
            "        return None;",
            "    }",
            "    NAMES.get(usize::from(offset)..usize::from(offset) + usize::from(len))",
            "}",
            "",
            "/// Return the canonical mnemonic, operation name, and register-presence bit.",
            "pub fn lookup_alias(encoding: u16) -> Option<(&'static str, &'static str, bool)> {",
            "    let index = ALIASES",
            "        .binary_search_by_key(&encoding, |entry| entry.encoding)",
            "        .ok()?;",
            "    let entry = ALIASES[index];",
            '    let mnemonic = ["at", "dc", "ic", "tlbi"][usize::from(entry.mnemonic)];',
            "    let offset = usize::from(entry.name_offset);",
            "    let name = NAMES.get(offset..offset + usize::from(entry.name_len))?;",
            "    Some((mnemonic, name, entry.has_register != 0))",
            "}",
            "",
            "#[cfg(test)]",
            "mod tests {",
            "    use super::*;",
            "",
            "    #[test]",
            "    fn packed_layout_and_directional_alias_are_pinned() {",
            "        assert_eq!(core::mem::size_of::<Entry>(), 8);",
            "        assert_eq!(core::mem::size_of::<AliasEntry>(), 8);",
            '        assert_eq!(lookup(0x9828, true), Some("dbgdtrrx_el0"));',
            '        assert_eq!(lookup(0x9828, false), Some("dbgdtrtx_el0"));',
            '        assert_eq!(lookup_alias(0x4418), Some(("tlbi", "vmalle1is", false)));',
            '        assert_eq!(lookup_alias(0x5ba9), Some(("ic", "ivau", true)));',
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    """Import or verify a checked-in structured corpus."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source", type=Path, help="Capstone basic-a64-instructions.s.cs"
    )
    parser.add_argument("output", type=Path, help="Glaurung JSON corpus path")
    parser.add_argument(
        "--sysreg-output",
        type=Path,
        help="optional generated packed Rust system-register table",
    )
    parser.add_argument(
        "--additional-sysreg-source",
        action="append",
        default=[],
        type=Path,
        help="additional AArch64 MC source contributing named system registers",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if output does not semantically match a fresh import",
    )
    args = parser.parse_args()
    imported = document(args.source)
    generated_sysregs = rust_sysreg_table([args.source, *args.additional_sysreg_source])
    if args.check:
        existing = json.loads(args.output.read_text())
        if existing != imported:
            raise SystemExit(f"stale Capstone corpus: regenerate {args.output}")
        if (
            args.sysreg_output is not None
            and args.sysreg_output.read_text() != generated_sysregs
        ):
            raise SystemExit(
                f"stale system-register table: regenerate {args.sysreg_output}"
            )
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(imported, indent=2) + "\n")
    if args.sysreg_output is not None:
        args.sysreg_output.parent.mkdir(parents=True, exist_ok=True)
        args.sysreg_output.write_text(generated_sysregs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
