import unittest

from src.objdump import imm_is_positive, process_mips_reloc


class TestMipsReloc(unittest.TestCase):
    def test_bare_hex_jump_target(self) -> None:
        """objdump prints jump/branch targets as bare hex.

        The row that used to raise, from a real IDO/MIPS object:

            18:	08000047 	j	11c <func_80096928+0x11c>
                    18: R_MIPS_26	.text
        """
        self.assertTrue(imm_is_positive("11c"))
        self.assertEqual(
            process_mips_reloc("18: R_MIPS_26\t.text", "j\t11c", ".text", "11c"),
            ".text+11c",
        )

    def test_decimal_and_hex_immediates_are_unchanged(self) -> None:
        for imm in ["4", "108", "0x4", "0x6c"]:
            self.assertTrue(imm_is_positive(imm), imm)
        self.assertEqual(
            process_mips_reloc(
                "74: R_MIPS_LO16\t.rodata", "lw\tv0,4", ".rodata", "4"
            ),
            "%lo(.rodata+4)",
        )

    def test_negative_immediates_keep_their_sign(self) -> None:
        for imm in ["-4", "-0x4", "-11c"]:
            self.assertFalse(imm_is_positive(imm), imm)
        self.assertEqual(
            process_mips_reloc(
                "74: R_MIPS_LO16\t.rodata", "lw\tv0,-4", ".rodata", "-4"
            ),
            "%lo(.rodata-4)",
        )

    def test_zero_is_positive_for_neither_base(self) -> None:
        for imm in ["0x0", "00", "0"]:
            self.assertFalse(imm_is_positive(imm), imm)

    def test_unparseable_immediate_does_not_raise(self) -> None:
        # Whatever else objdump may print, a shape we cannot parse must not
        # take the whole candidate down with it.
        self.assertTrue(imm_is_positive("<target>"))
        self.assertFalse(imm_is_positive("-<target>"))


if __name__ == "__main__":
    unittest.main()
