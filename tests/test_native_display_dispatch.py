"""Generated display provider preserves complete state across native-call yields."""
import unittest
import test_native_graphics_dispatch as fixture

class DisplayDispatchTests(unittest.TestCase):
    def test_native_vi_initializer_quota_vectors_and_owned_surface_cleanup(self):
        fixture.GraphicsDispatchTests.run_native(self,display=True)

if __name__=='__main__':unittest.main()
