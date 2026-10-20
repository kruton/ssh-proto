"""Offline regression tests for the upstream/extraction verification gate."""

import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import vendor_bouncycastle as vendor


class ArchiveInputTest(unittest.TestCase):
    def test_cli_rejects_unexpected_artifact_before_reading_archive(self):
        with patch.object(vendor.sys, "argv", ["vendor_bouncycastle.py"]), \
                patch.object(vendor, "MANIFEST") as manifest, \
                patch.object(vendor, "read_archive") as download:
            manifest.read_text.return_value = json.dumps({"artifact": "unexpected:artifact"})
            with self.assertRaisesRegex(ValueError, "Unexpected upstream artifact"):
                vendor.main()
            download.assert_not_called()

    def test_check_failure_reports_review_instructions_without_updating_manifest(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as jar:
            jar.writestr(vendor.LICENSE_ENTRY, b"license")
        with patch.object(vendor.sys, "argv", ["vendor_bouncycastle.py", "--check"]), \
                patch.object(vendor, "MANIFEST") as manifest, \
                patch.object(vendor, "SOURCE_FILES", []), \
                patch.object(vendor, "read_archive", return_value=archive.getvalue()), \
                patch.object(vendor, "extract", return_value={}), \
                patch.object(vendor, "verify", return_value=["UPSTREAM CHANGED: example"]), \
                patch.object(vendor.sys, "stderr", io.StringIO()) as stderr:
            manifest.read_text.return_value = json.dumps({
                "artifact": "org.bouncycastle:bcprov-jdk18on", "version": "1.86",
            })
            self.assertEqual(1, vendor.main())
            self.assertIn("UPSTREAM CHANGED: example", stderr.getvalue())
            self.assertIn("Review upstream against reviewedVersion", stderr.getvalue())
            manifest.write_text.assert_not_called()

    def test_update_writes_extracted_sources_license_and_reproducible_manifest(self):
        originals = {
            vendor.NTRU + "Utils.java": b"package org.bouncycastle.pqc.crypto.ntruprime;\nclass Utils {\n}\n",
            vendor.PREFIX + "crypto/Example.java": b"package org.bouncycastle.crypto;\npublic class Example {}\n",
            vendor.LICENSE_ENTRY: b"upstream license",
        }
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as jar:
            for name, data in originals.items():
                jar.writestr(name, data)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_file = root / "upstream.json"
            manifest_file.write_text(json.dumps({
                "artifact": "org.bouncycastle:bcprov-jdk18on", "version": "1.86", "reviewedVersion": "1.85",
            }))
            output = root / "java"
            license_file = root / "LICENSE.md"
            destination = vendor.destination
            with patch.object(vendor.sys, "argv", ["vendor_bouncycastle.py", "--update", "--archive-stdin"]), \
                    patch.object(vendor.sys, "stdin") as stdin, \
                    patch.object(vendor.sys, "stdout", io.StringIO()), \
                    patch.object(vendor, "MANIFEST", manifest_file), \
                    patch.object(vendor, "SOURCE_FILES", [name for name in originals if name != vendor.LICENSE_ENTRY]), \
                    patch.object(vendor, "destination", side_effect=lambda name: destination(name, output, license_file)):
                stdin.buffer.read.return_value = archive.getvalue()
                self.assertEqual(0, vendor.main())
            manifest = json.loads(manifest_file.read_text())
            self.assertEqual("1.86", manifest["reviewedVersion"])
            self.assertEqual(b"upstream license", license_file.read_bytes())
            self.assertIn("class Example {}", (output / "sntrup" / "Example.java").read_text())
            self.assertNotIn("public class", (output / "sntrup" / "Example.java").read_text())
            self.assertEqual([], vendor.verify(manifest, originals, vendor.extract(originals), output, license_file))

    def test_download_uses_manifest_version_and_fixed_maven_url(self):
        with patch.object(vendor.urllib.request, "urlopen") as download:
            download.return_value.__enter__.return_value.read.return_value = b"archive"
            self.assertEqual(b"archive", vendor.read_archive("1.86"))
        download.assert_called_once_with(
            "https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk18on/"
            "1.86/bcprov-jdk18on-1.86-sources.jar", timeout=60)

    def test_cli_selects_stdin_or_download(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as jar:
            jar.writestr(vendor.LICENSE_ENTRY, b"license")
        manifest = {"artifact": "org.bouncycastle:bcprov-jdk18on", "version": "1.86"}
        for flags in ([], ["--archive-stdin"]):
            with self.subTest(flags=flags), \
                    patch.object(vendor.sys, "argv", ["vendor_bouncycastle.py", "--check", *flags]), \
                    patch.object(vendor.sys, "stdin") as stdin, \
                    patch.object(vendor, "MANIFEST") as manifest_file, \
                    patch.object(vendor, "SOURCE_FILES", []), \
                    patch.object(vendor, "read_archive", return_value=archive.getvalue()) as download, \
                    patch.object(vendor, "extract", return_value={}) as extract, \
                    patch.object(vendor, "verify", return_value=[]), \
                    patch.object(vendor.sys, "stdout", io.StringIO()):
                manifest_file.read_text.return_value = json.dumps(manifest)
                stdin.buffer.read.return_value = archive.getvalue()
                self.assertEqual(0, vendor.main())
                extract.assert_called_once_with({vendor.LICENSE_ENTRY: b"license"})
                if flags:
                    stdin.buffer.read.assert_called_once_with()
                    download.assert_not_called()
                else:
                    stdin.buffer.read.assert_not_called()
                    download.assert_called_once_with("1.86")

    def test_cli_reports_empty_or_malformed_stdin_archive(self):
        for data in (b"", b"not a zip archive"):
            with self.subTest(data=data):
                result = subprocess.run(
                    [sys.executable, vendor.__file__, "--check", "--archive-stdin"],
                    input=data, capture_output=True, check=False)
                self.assertEqual(1, result.returncode)
                self.assertIn(b"Bouncy Castle source verification failed:", result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_cli_rejects_removed_archive_option(self):
        result = subprocess.run(
            [sys.executable, vendor.__file__, "--archive", "unused.jar"],
            capture_output=True, check=False)
        self.assertEqual(2, result.returncode)
        self.assertIn(b"unrecognized arguments: --archive", result.stderr)


class VerificationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "java"
        self.license = Path(self.temp.name) / "LICENSE.md"
        self.name = vendor.NTRU + "Example.java"
        self.originals = {self.name: b"original upstream bytes", vendor.POLY: b"original Poly1305",
                          vendor.PACK: b"original Pack", vendor.LICENSE_ENTRY: b"license"}
        self.generated = {self.name: b"adapted Java bytes", vendor.POLY: b"adapted Poly1305",
                          vendor.PACK: b"adapted Pack", vendor.LICENSE_ENTRY: b"license"}
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
        for name in self.originals:
            with self.subTest(name=name):
                original = self.originals[name]
                self.originals[name] += b" upstream-only comment or helper change"
                self.assertTrue(any("UPSTREAM CHANGED" in e for e in self.verify()))
                self.originals[name] = original

    def test_adaptation_change_fails_even_when_upstream_is_unchanged(self):
        self.generated[self.name] += b" generator changed"
        errors = self.verify()
        self.assertTrue(any("EXTRACTION CHANGED" in e for e in errors))
        self.assertTrue(any("VENDORED FILE DIFFERS" in e for e in errors))

    def test_local_edit_is_detected(self):
        for name in self.generated:
            with self.subTest(name=name):
                path = vendor.destination(name, self.output, self.license)
                original = path.read_bytes()
                path.write_bytes(b"local drift")
                self.assertTrue(any("VENDORED FILE DIFFERS" in e for e in self.verify()))
                path.write_bytes(original)

    def test_missing_local_file_is_detected(self):
        (self.output / "sntrup" / "Example.java").unlink()
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
    def test_combines_separate_algorithm_extractions(self):
        originals = {vendor.POLY: b"poly", vendor.PACK: b"pack", vendor.LICENSE_ENTRY: b"license",
                     vendor.NTRU + "Utils.java": b"utils"}
        sntrup = {vendor.NTRU + "Utils.java": b"generated utils", vendor.LICENSE_ENTRY: b"license"}
        poly = {vendor.POLY: b"generated poly", vendor.PACK: b"generated pack", vendor.LICENSE_ENTRY: b"license"}
        with patch.object(vendor, "extract_sntrup", return_value=sntrup) as sntrup_extract, \
                patch.object(vendor, "extract_poly1305", return_value=poly) as poly_extract:
            self.assertEqual(sntrup | poly, vendor.extract(originals))
        sntrup_extract.assert_called_once_with({vendor.NTRU + "Utils.java": b"utils", vendor.LICENSE_ENTRY: b"license"})
        poly_extract.assert_called_once_with(originals)


    def test_adapts_crypto_dependencies_and_adds_private_key_erasure(self):
        originals = {
            vendor.NTRU + "Utils.java": b"class Utils {\n}\n",
            vendor.NTRU + "SNTRUPrimePrivateKeyParameters.java": b"""package org.bouncycastle.pqc.crypto.ntruprime;
import org.bouncycastle.util.Arrays;
public class SNTRUPrimePrivateKeyParameters {
    Object a = Arrays.clone(f);
    Object b = Arrays.copyOfRange(f, 0, 1);
    boolean c = Arrays.constantTimeAreEqual(f, ginv);
    Object random = CryptoServicesRegistrar.getSecureRandom();
    Object supplied = CryptoServicesRegistrar.getSecureRandom(random);
}
""",
            vendor.LICENSE_ENTRY: b"license",
        }
        result = vendor.extract(originals)
        source = result[vendor.NTRU + "SNTRUPrimePrivateKeyParameters.java"].decode()
        self.assertIn("f.clone()", source)
        self.assertIn("java.util.Arrays.copyOfRange(f, 0, 1)", source)
        self.assertIn("java.security.MessageDigest.isEqual(f, ginv)", source)
        self.assertIn("new SecureRandom()", source)
        self.assertIn("(random != null ? random : new SecureRandom())", source)
        for field in ("f", "ginv", "pk", "rho", "hash"):
            self.assertIn(f"java.util.Arrays.fill({field}, (byte)0);", source)
        self.assertNotIn("org.bouncycastle", source)
        self.assertEqual(b"license", result[vendor.LICENSE_ENTRY])

    def test_unadapted_upstream_dependency_fails_extraction(self):
        with self.assertRaisesRegex(ValueError, "Unadapted BC dependency"):
            vendor.extract({
                vendor.NTRU + "Utils.java": b"class Utils {\n}\n",
                vendor.NTRU + "Caller.java": b"class Caller { Object value = CryptoServicesRegistrar.newMethod(); }",
                vendor.LICENSE_ENTRY: b"license",
            })

    def test_overloaded_upstream_helper_fails_extraction(self):
        with self.assertRaisesRegex(ValueError, "Upstream Utils now overloads helper"):
            vendor.client_utils({vendor.NTRU + "Utils.java": """class Utils {
    static int helper()
    {
        return 1;
    }
    static int helper(int value)
    {
        return value;
    }
}
"""})

    def test_small_polynomial_adaptation_requires_each_upstream_shift_once(self):
        shifts = [f"        x += (byte)(sp[spIndex++] + 1) << {shift};" for shift in (2, 4, 6)]
        for body in ("\n".join(shifts), "\n".join(shifts[:-1]), "\n".join(shifts + shifts[:1])):
            sources = {
                vendor.NTRU + "Caller.java": "class Caller { void call() { Utils.getEncodedSmallPolynomial(); } }",
                vendor.NTRU + "Utils.java": (
                    "class Utils {\n    protected static void getEncodedSmallPolynomial()\n    {\n"
                    + body + "\n    }\n}\n"),
            }
            with self.subTest(body=body):
                if body == "\n".join(shifts):
                    result = vendor.client_utils(sources)
                    for shift in (2, 4, 6):
                        self.assertIn(f"x = (byte)(x + (((sp[spIndex++] + 1) & 0xff) << {shift}));", result)
                else:
                    with self.assertRaisesRegex(ValueError, "Upstream small-polynomial encoding changed"):
                        vendor.client_utils(sources)

    def test_transitive_math_helpers_are_retained_and_unrelated_aes_is_removed(self):
        sources = {
            vendor.NTRU + "Caller.java": "class Caller { int x() { return Utils.outer(); } }",
            vendor.NTRU + "Utils.java": """class Utils {
    protected static int outer()
    {
        return inner() + inner();
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
