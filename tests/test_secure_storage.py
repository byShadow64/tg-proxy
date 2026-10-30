import os
import unittest

from utils.secure_storage import protect_token, unprotect_token


@unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
class DpapiStorageTest(unittest.TestCase):
    def test_token_round_trip_is_encrypted(self):
        token = "test-helper-token-0123456789abcdef"
        stored = protect_token(token)
        self.assertNotIn(token, stored)
        self.assertEqual(unprotect_token(stored), token)

    def test_malformed_ciphertext_is_rejected(self):
        with self.assertRaises(ValueError):
            unprotect_token("not base64!")


if __name__ == "__main__":
    unittest.main()
