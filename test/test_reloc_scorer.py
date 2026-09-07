import os
import tempfile
import unittest
from typing import Dict

from src.reloc_scorer import (
    MASK_FULL,
    MASK_NO_IMM16,
    MASK_OPCODE,
    RelocMaskedScorer,
    mask_for,
    masked_diff,
    parse_listing,
)
from src.scorer import Scorer

# objdump -drz of a small object built with gcc 2.7.2 (MIPS I, -O2 -G0): a %hi/%lo
# pair, a jal, two branches, and a second function.
LISTING = """
fixture.o:     file format elf32-tradlittlemips


Disassembly of section .text:

00000000 <fixture>:
   0:\t27bdffd8 \taddiu\tsp,sp,-40
   4:\tafb1001c \tsw\ts1,28(sp)
   8:\t00808821 \tmove\ts1,a0
   c:\tafb00018 \tsw\ts0,24(sp)
  10:\t00008021 \tmove\ts0,zero
  14:\t00002021 \tmove\ta0,zero
  18:\tafbf0024 \tsw\tra,36(sp)
  1c:\t1a200013 \tblez\ts1,6c <fixture+0x6c>
  20:\tafb20020 \tsw\ts2,32(sp)
  24:\t3c120000 \tlui\ts2,0x0
\t\t\t24: R_MIPS_HI16\ttable
  28:\t26520000 \taddiu\ts2,s2,0
\t\t\t28: R_MIPS_LO16\ttable
  2c:\t32020007 \tandi\tv0,s0,0x7
  30:\t00021080 \tsll\tv0,v0,0x2
  34:\t00521021 \taddu\tv0,v0,s2
  38:\t8c420000 \tlw\tv0,0(v0)
  3c:\t00000000 \tnop
  40:\t00822021 \taddu\ta0,a0,v0
  44:\t28820065 \tslti\tv0,a0,101
  48:\t14400004 \tbnez\tv0,5c <fixture+0x5c>
  4c:\t00000000 \tnop
  50:\t0c000000 \tjal\t0 <fixture>
\t\t\t50: R_MIPS_26\thelper
  54:\t00000000 \tnop
  58:\t00402021 \tmove\ta0,v0
  5c:\t26100001 \taddiu\ts0,s0,1
  60:\t0211102a \tslt\tv0,s0,s1
  64:\t1440fff2 \tbnez\tv0,30 <fixture+0x30>
  68:\t32020007 \tandi\tv0,s0,0x7
  6c:\t00801021 \tmove\tv0,a0
  70:\t8fbf0024 \tlw\tra,36(sp)
  74:\t8fb20020 \tlw\ts2,32(sp)
  78:\t8fb1001c \tlw\ts1,28(sp)
  7c:\t8fb00018 \tlw\ts0,24(sp)
  80:\t27bd0028 \taddiu\tsp,sp,40
  84:\t03e00008 \tjr\tra
  88:\t00000000 \tnop

0000008c <other>:
  8c:\t00041040 \tsll\tv0,a0,0x1
  90:\t00441021 \taddu\tv0,v0,a0
  94:\t00052883 \tsra\ta1,a1,0x2
  98:\t03e00008 \tjr\tra
  9c:\t00451026 \txor\tv0,v0,a1
"""


def listing(edits: Dict[str, str]) -> str:
    text = LISTING
    for old, new in edits.items():
        assert old in text, old
        text = text.replace(old, new)
    return text


class TestParse(unittest.TestCase):
    def test_whole_text_and_one_function(self) -> None:
        whole = parse_listing(LISTING.splitlines())
        self.assertEqual(len(whole), 40)
        only = parse_listing(LISTING.splitlines(), "other")
        self.assertEqual(
            [i.word for i in only],
            [0x00041040, 0x00441021, 0x00052883, 0x03E00008, 0x00451026],
        )
        # unknown function name -> whole .text
        self.assertEqual(len(parse_listing(LISTING.splitlines(), "no_such_fn")), 40)

    def test_relocations_are_attached(self) -> None:
        insns = parse_listing(LISTING.splitlines(), "fixture")
        by_off = {i.offset: i for i in insns}
        self.assertEqual(
            (by_off[0x24].reloc_kind, by_off[0x24].reloc_op), ("HI16", "table")
        )
        self.assertEqual(
            (by_off[0x28].reloc_kind, by_off[0x28].reloc_op), ("LO16", "table")
        )
        self.assertEqual(
            (by_off[0x50].reloc_kind, by_off[0x50].reloc_op), ("26", "helper")
        )
        self.assertIsNone(by_off[0x48].reloc_kind)  # branch: no reloc

    def test_masks(self) -> None:
        self.assertEqual(mask_for("26"), MASK_OPCODE)
        self.assertEqual(mask_for("HI16"), MASK_NO_IMM16)
        self.assertEqual(mask_for("LO16"), MASK_NO_IMM16)
        self.assertEqual(mask_for(None), MASK_FULL)


class TestMaskedDiff(unittest.TestCase):
    def insns(self, text: str = LISTING) -> list:
        return parse_listing(text.splitlines(), "fixture")

    def test_identical_is_zero(self) -> None:
        self.assertEqual(masked_diff(self.insns(), self.insns())[0], 0)

    def test_link_time_fields_are_masked(self) -> None:
        # same code, different link-time values in the jal target and the %hi/%lo pair
        cand = listing(
            {
                "0c000000 ": "0c004800 ",
                "3c120000 ": "3c128002 ",
                "26520000 ": "26522a40 ",
            }
        )
        self.assertEqual(masked_diff(self.insns(cand), self.insns())[0], 0)

    def test_other_symbol_at_a_relocated_slot_counts(self) -> None:
        cand = listing({"R_MIPS_26\thelper": "R_MIPS_26\tother_helper"})
        score, diffs = masked_diff(self.insns(cand), self.insns())
        self.assertEqual((score, diffs[0][3]), (1, "relocation symbol"))
        cand = listing(
            {
                "R_MIPS_HI16\ttable": "R_MIPS_HI16\ttable2",
                "R_MIPS_LO16\ttable": "R_MIPS_LO16\ttable2",
            }
        )
        self.assertEqual(masked_diff(self.insns(cand), self.insns())[0], 2)

    def test_register_branch_and_opcode_differences_count(self) -> None:
        cand = listing({"00521021 ": "00531021 "})  # s3 instead of s2
        score, diffs = masked_diff(self.insns(cand), self.insns())
        self.assertEqual((score, diffs[0][3]), (1, "operand"))
        cand = listing({"14400004 ": "14400005 "})  # different branch target
        self.assertEqual(masked_diff(self.insns(cand), self.insns())[0], 1)
        cand = listing({"8c420000 ": "94420000 "})  # lw -> lhu
        score, diffs = masked_diff(self.insns(cand), self.insns())
        self.assertEqual((score, diffs[0][3]), (1, "opcode"))

    def test_length_difference_counts_per_instruction(self) -> None:
        cand = LISTING.replace("  88:\t00000000 \tnop\n", "")
        score, diffs = masked_diff(self.insns(cand), self.insns())
        self.assertEqual((score, diffs[-1][3]), (1, "length"))

    def test_internal_jump_targets_are_compared(self) -> None:
        # j to a label in the same function: R_MIPS_26 against .text, compared by target
        target = LISTING.replace(
            "  4c:\t00000000 \tnop\n",
            "  4c:\t08000018 \tj\t60 <fixture+0x60>\n\t\t\t4c: R_MIPS_26\t.text\n",
        )
        cand = LISTING.replace(
            "  4c:\t00000000 \tnop\n",
            "  4c:\t0800001b \tj\t6c <fixture+0x6c>\n\t\t\t4c: R_MIPS_26\t.text\n",
        )
        t, c = self.insns(target), self.insns(cand)
        self.assertEqual(masked_diff(t, t)[0], 0)
        score, diffs = masked_diff(c, t)
        self.assertEqual((score, diffs[0][3]), (1, "jump target"))


class TestScorer(unittest.TestCase):
    def test_scorer_end_to_end_with_a_stand_in_objdump(self) -> None:
        # objdump_command=cat lets a listing file stand in for an object
        # get_arch() only reads the first 20 bytes (ident + e_machine)
        header = b"\x7fELF\x01\x01\x01" + bytes(9) + b"\x01\x00\x08\x00"

        def fake_object(path: str, text: str) -> str:
            with open(path, "wb") as f:
                f.write(header + b"\n" + text.encode())
            return path

        with tempfile.TemporaryDirectory() as d:
            target = fake_object(os.path.join(d, "target.o"), LISTING)
            same = fake_object(
                os.path.join(d, "same.o"), listing({"0c000000 ": "0c004800 "})
            )
            worse = fake_object(
                os.path.join(d, "worse.o"), listing({"00521021 ": "00531021 "})
            )
            scorer = RelocMaskedScorer(target, fn_name="fixture", objdump_command="cat")
            self.assertIsInstance(scorer, Scorer)
            self.assertEqual(scorer.score(same)[0], 0)
            self.assertEqual(scorer.score(worse)[0], 1)
            self.assertEqual(scorer.score(None)[0], Scorer.PENALTY_INF)
            self.assertNotEqual(scorer.score(same)[1], scorer.score(worse)[1])


if __name__ == "__main__":
    unittest.main()
