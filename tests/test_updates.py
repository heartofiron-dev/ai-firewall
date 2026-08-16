import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from ai_firewall.model import LinearModel
from ai_firewall.updates import (
    create_signed_bundle, generate_signing_keys, install_signed_bundle,
    rollback_model, verify_signed_bundle,
)


ROOT = Path(__file__).resolve().parents[1]


try:
    import cryptography  # noqa: F401
except ImportError:
    HAS_CRYPTO = False
else:
    HAS_CRYPTO = True


@unittest.skipUnless(HAS_CRYPTO, "cryptography optional dependency is not installed")
class UpdateTests(unittest.TestCase):
    def test_signed_fixed_version_install_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, public = root / "private.pem", root / "public.pem"
            bundle, target = root / "model.aifw", root / "active.json"
            generate_signing_keys(private, public)
            manifest = create_signed_bundle(
                ROOT / "models" / "baseline.json", private, bundle, version="1.0.0",
            )
            self.assertEqual(manifest["algorithm"], "ed25519")
            target.write_text((ROOT / "models" / "baseline.json").read_text(encoding="utf-8"), encoding="utf-8")
            installed = install_signed_bundle(
                bundle, public, target, expected_version="1.0.0",
            )
            self.assertTrue(installed["installed"])
            LinearModel.load(target)
            rolled = rollback_model(target)
            self.assertTrue(rolled["rolled_back"])
            LinearModel.load(target)

    def test_wrong_version_and_tampered_model_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, public = root / "private.pem", root / "public.pem"
            bundle = root / "model.aifw"
            generate_signing_keys(private, public)
            create_signed_bundle(
                ROOT / "models" / "baseline.json", private, bundle, version="1.0.0",
            )
            with self.assertRaisesRegex(ValueError, "固定"):
                verify_signed_bundle(bundle, public, expected_version="1.0.1")

            tampered = root / "tampered.aifw"
            with zipfile.ZipFile(bundle, "r") as source, zipfile.ZipFile(tampered, "w") as output:
                for name in source.namelist():
                    payload = source.read(name)
                    if name == "model.json":
                        data = json.loads(payload)
                        data["bias"] = float(data["bias"]) + 1
                        payload = json.dumps(data).encode()
                    output.writestr(name, payload)
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_signed_bundle(tampered, public, expected_version="1.0.0")


if __name__ == "__main__":
    unittest.main()
