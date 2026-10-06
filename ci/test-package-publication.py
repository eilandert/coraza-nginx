"""Check release dependencies and the tested-artifact publication gate."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/package.yml"
GATE = ROOT / "ci/package-publication-gate.sh"


def jobs():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


class PublicationWorkflowTests(unittest.TestCase):
    def test_all_install_cells_precede_publication(self):
        workflow = jobs()
        self.assertEqual(workflow["install-test"]["needs"], "package")
        self.assertIn("install-test", workflow["publish"]["needs"])
        self.assertIn("package", workflow["publish"]["needs"])
        self.assertEqual(workflow["install-test"]["strategy"]["matrix"]["pkg_type"], ["deb", "rpm"])
        for axis in ("arch", "nginx_version"):
            self.assertEqual(workflow["publish"]["strategy"]["matrix"][axis],
                             workflow["install-test"]["strategy"]["matrix"][axis])
        self.assertFalse(any("cosign" in str(step) or "action-gh-release" in str(step)
                             for step in workflow["package"]["steps"]))
        package_steps = workflow["package"]["steps"]
        install_steps = workflow["install-test"]["steps"]
        publish_steps = workflow["publish"]["steps"]
        upload = next(step for step in package_steps if step["name"] == "Upload packages as artifacts for install tests")
        download = next(step for step in install_steps if step["name"] == "Download packages artifact")
        publish_download = next(step for step in publish_steps if step["name"] == "Download tested packages")
        self.assertEqual(upload["with"]["name"], download["with"]["name"])
        self.assertEqual(upload["with"]["name"], publish_download["with"]["name"])
        receipt_upload = next(step for step in install_steps if step["name"] == "Upload verification receipt")
        receipt_download = next(step for step in publish_steps if step["name"] == "Download verification receipts")
        self.assertEqual(receipt_upload["with"]["name"].rsplit("-", 1)[0] + "-*",
                         receipt_download["with"]["pattern"])
        self.assertTrue(receipt_download["with"]["merge-multiple"])
        names = [step["name"] for step in publish_steps]
        self.assertLess(names.index("Check tested package identity"),
                        names.index("Sign packages with cosign (keyless)"))
        self.assertLess(names.index("Sign packages with cosign (keyless)"),
                        names.index("Upload packages and signatures to release"))

    def test_bad_install_fixture_blocks_mock_publication(self):
        workflow = jobs()
        # Execute the workflow's needs graph with a harmless fixture standing in
        # for the four real smoke-test cells and a mocked publication action.
        for bad_cell in (None, ("arm64", "rpm")):
            results = {"package": True}
            cells = [(arch, kind) for arch in workflow["install-test"]["strategy"]["matrix"]["arch"]
                     for kind in workflow["install-test"]["strategy"]["matrix"]["pkg_type"]]
            fixtures = {cell: b"invalid package" if cell == bad_cell else b"valid package"
                        for cell in cells}
            results["install-test"] = all(data == b"valid package" for data in fixtures.values())
            published = []
            if all(results[dependency] for dependency in workflow["publish"]["needs"]):
                published.append("mock release upload")
            self.assertEqual(published, [] if bad_cell else ["mock release upload"])

    def test_verified_packages_pass_and_changed_package_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = os.environ | {"RELEASE_TAG": "v1.2.3", "NGINX_VERSION": "1.30.3", "DEB_ARCH": "amd64"}
            for kind in ("deb", "rpm"):
                package = root / f"coraza-nginx_1.2.3_nginx1.30.3_amd64.{kind}"
                package.write_bytes(f"valid {kind}".encode())
                digest = hashlib.sha256(package.read_bytes()).hexdigest()
                (root / f"verified-{kind}.sha256").write_text(f"{digest}  {package.name}\n")
            command = ["bash", str(GATE)]
            good = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, check=False)
            published = []
            if good.returncode == 0:
                published.append("mock release upload")
            self.assertEqual(published, ["mock release upload"], good.stderr)
            published.clear()
            (root / "coraza-nginx_1.2.3_nginx1.30.3_amd64.rpm").write_bytes(b"invalid fixture")
            bad = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, check=False)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("verification receipt does not match", bad.stderr)
            self.assertEqual(published, [])
            (root / "verified-rpm.sha256").unlink()
            missing = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, check=False)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("missing verification receipt", missing.stderr)


if __name__ == "__main__":
    unittest.main()
