"""Offline regression tests for the upstream/extraction verification gate."""

from pathlib import Path
import tempfile
import unittest

import vendor_sntrup as vendor


class VerificationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "java"
        self.license = Path(self.temp.name) / "LICENSE.md"
        self.name = vendor.NTRU + "Example.java"
        self.originals = {self.name: b"original upstream bytes", vendor.LICENSE_ENTRY: b"license"}
        self.generated = {self.name: b"adapted Java bytes", vendor.LICENSE_ENTRY: b"license"}
        self.manifest = {"version": "1.86", "reviewedVersion": "1.86", "files": {
            name: {"originalSha256": vendor.sha256(data),
                   "extractedSha256": vendor.sha256(self.generated[name])}
            for name, data in self.originals.items()
        }}
        for name, data in self.generated.items():
            path = vendor.destination(name, self.output, self.license)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def verify(self):
        return vendor.verify(self.manifest, self.originals, self.generated, self.output, self.license)

    def test_unchanged_upstream_release_passes(self):
        self.manifest["version"] = "1.87"
        self.assertEqual([], self.verify())

    def test_upstream_change_fails_even_when_extracted_output_is_unchanged(self):
        self.originals[self.name] += b" upstream-only comment or helper change"
        self.assertTrue(any("UPSTREAM CHANGED" in e for e in self.verify()))

    def test_adaptation_change_fails_even_when_upstream_is_unchanged(self):
        self.generated[self.name] += b" generator changed"
        errors = self.verify()
        self.assertTrue(any("EXTRACTION CHANGED" in e for e in errors))
        self.assertTrue(any("VENDORED FILE DIFFERS" in e for e in errors))

    def test_local_edit_is_detected(self):
        (self.output / "Example.java").write_bytes(b"local drift")
        self.assertTrue(any("VENDORED FILE DIFFERS" in e for e in self.verify()))

    def test_missing_local_file_is_detected(self):
        (self.output / "Example.java").unlink()
        self.assertTrue(any("VENDORED FILE DIFFERS" in e for e in self.verify()))

    def test_license_change_is_detected(self):
        self.originals[vendor.LICENSE_ENTRY] = b"new upstream license"
        self.assertTrue(any("UPSTREAM CHANGED: META-INF/LICENSE.md" in e for e in self.verify()))

    def test_unexpected_source_file_is_detected(self):
        (self.output / "Extra.java").write_bytes(b"untracked vendor code")
        self.assertTrue(any("Unexpected vendored" in e for e in self.verify()))

    def test_manifest_inventory_change_is_detected(self):
        self.manifest["files"]["removed.java"] = {}
        self.assertTrue(any("inventory" in e for e in self.verify()))

    def test_version_cannot_change_download_host_or_path(self):
        with self.assertRaises(ValueError):
            vendor.read_archive("../../unexpected")


class ExtractionTest(unittest.TestCase):
    def test_transitive_math_helpers_are_retained_and_unrelated_aes_is_removed(self):
        sources = {
            vendor.NTRU + "Caller.java": "class Caller { int x() { return Utils.outer(); } }",
            vendor.NTRU + "Utils.java": """class Utils {
    protected static int outer()
    {
        return inner();
    }
    private static int inner()
    {
        return 7;
    }
    private static void unusedAES()
    {
        new AESEngine();
    }
    protected static byte[] getHashWithPrefix(byte[] prefix, byte[] hashInput)
    {
        return null;
    }
}
""",
        }
        result = vendor.client_utils(sources)
        self.assertIn("return inner()", result)
        self.assertIn("return 7", result)
        self.assertNotIn("AES", result)


if __name__ == "__main__":
    unittest.main()
