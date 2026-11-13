"""The common differential matrix links independently compiled generated units."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from lifter_validation import compile_library, validate_program
from lifter_validation_types import Program, Trial


class TranslationUnitTests(unittest.TestCase):
    def test_independent_units_keep_exports_state_and_leaf_descriptors(self):
        programs=[
            Program('unit_move',[0xd28000e0],[Trial(0,[0]*31,0x800000,0,1)]),
            Program('unit_leaf',[0xd2800120,0xd65f03c0],
                    [Trial(0,[0]*31,0x800000,0,2)],leaf=True),
        ]
        lib,build=compile_library(programs,os.environ.get('OOT_LIFTER_COMPILER','cmake'),
                                  split_programs=True)
        self.assertEqual(sum(validate_program(lib,p) for p in programs),2)
        self.assertIsNotNone(lib.oot_leaf_descriptor_unit_leaf)
        sources=build['translation_units']
        self.assertEqual(len(sources),2)
        texts=[(Path(build['directory'])/p).read_text() for p in sources]
        self.assertTrue(all(('oot_lift_unit_move' in t) != ('oot_lift_unit_leaf' in t) for t in texts))


if __name__=='__main__':unittest.main()
