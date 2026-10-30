"""Artifact inputs remain untrusted bytes until hash, bundle and approval verify."""
import base64,hashlib,json,zipfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock,patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from release_tools import github,trust
from release_tools.bundle import load_bundle
from tests.test_release_bundle import PreparedBundleMixin
from tests.release_fixtures import sign_test_approval

class ArtifactInputTest(PreparedBundleMixin,TestCase):
    def setUp(self):
        self.prepare_fixture()
        self.bundle=load_bundle(self.root)
        key=Ed25519PrivateKey.generate()
        public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        p=patch.dict(trust.TRUSTED_APPROVAL_KEYS,{"test-artifact":base64.b64encode(public).decode()});p.start();self.addCleanup(p.stop)
        (self.root/"approval.json").write_text(json.dumps(sign_test_approval(self.bundle,key,"test-artifact")),encoding="utf-8")
        self.archive=self.folder/"input.zip"
        with zipfile.ZipFile(self.archive,"w") as archive:
            for name in sorted(github._BUNDLE_FILES):archive.write(self.root/name,name)
        self.raw=self.archive.read_bytes();self.digest=hashlib.sha256(self.raw).hexdigest()

    def client(self,raw=None,tag=None):
        raw=self.raw if raw is None else raw
        client=Mock()
        client.json.return_value={"draft":True,"tag_name":tag or "publisher-input-"+self.bundle.bundle_id}
        client.pages.return_value=[{"id":34,"name":github.INPUT_ASSET,"size":len(raw)}]
        def get(*args,**kwargs):kwargs["sink"](raw);return b"",len(raw)
        client._request.side_effect=get
        return client

    def test_fetch_is_raw_only_and_never_extracts_or_loads_even_invalid_zip(self):
        raw=b"deliberately-not-a-zip-no-code-executed";client=self.client(raw)
        path=self.folder/"fetched.zip"
        with patch("release_tools.bundle.load_bundle",side_effect=AssertionError("must not load")),patch("release_tools.trust.verify_approval",side_effect=AssertionError("must not verify at fetch")):
            identity=github.download_draft_archive("owner/repo","synthetic",12,34,hashlib.sha256(raw).hexdigest(),path,_client=client)
        self.assertEqual(identity,self.bundle.bundle_id);self.assertEqual(path.read_bytes(),raw)
        self.assertEqual([call[0] for call in client.mock_calls],["json","pages","_request"])

    def test_fetch_rejects_bad_draft_identity_and_wrong_sha(self):
        for tag in ("publisher-input-x","publisher-input-"+"A"*64,"publisher-input-"+"b"*64+"\nextra","v1.2.3"):
            with self.subTest(tag=tag),self.assertRaisesRegex(github.GitHubError,"draft_input_required"):
                github.download_draft_archive("owner/repo","synthetic",12,34,self.digest,self.folder/"absent.zip",_client=self.client(tag=tag))
        with self.assertRaisesRegex(github.GitHubError,"draft_input_hash"):
            github.download_draft_archive("owner/repo","synthetic",12,34,"0"*64,self.folder/"bad-sha.zip",_client=self.client())

    def test_local_load_rechecks_real_signature_and_exact_bundle_identity(self):
        result=github.load_local_bundle_archive(self.archive,self.digest,self.bundle.bundle_id,self.folder/"loaded")
        self.assertEqual(result.bundle_id,self.bundle.bundle_id)
        with self.assertRaisesRegex(github.GitHubError,"draft_input_conflict"):
            github.load_local_bundle_archive(self.archive,self.digest,"0"*64,self.folder/"wrong-id")

    def test_tampered_local_archive_fails_before_any_extraction(self):
        self.archive.write_bytes(self.raw+b"tampered")
        output=self.folder/"must-not-exist"
        with self.assertRaisesRegex(github.GitHubError,"draft_input_hash"):
            github.load_local_bundle_archive(self.archive,self.digest,self.bundle.bundle_id,output)
        self.assertFalse(output.exists())

    def test_rehashed_signature_tamper_still_fails_cryptographically(self):
        bad=self.folder/"bad-approval.zip"
        with zipfile.ZipFile(self.archive) as old,zipfile.ZipFile(bad,"w") as new:
            for name in old.namelist():
                data=old.read(name)
                if name=="approval.json":
                    value=json.loads(data);value["signature"]=base64.b64encode(b"x"*64).decode();data=json.dumps(value).encode()
                new.writestr(name,data)
        with self.assertRaisesRegex(github.GitHubError,"approval_signature"):
            github.load_local_bundle_archive(bad,hashlib.sha256(bad.read_bytes()).hexdigest(),self.bundle.bundle_id,self.folder/"bad-approval")

    def test_extra_path_rejected_even_with_matching_transport_hash(self):
        bad=self.folder/"extra.zip"
        with zipfile.ZipFile(self.archive) as old,zipfile.ZipFile(bad,"w") as new:
            for name in old.namelist():new.writestr(name,old.read(name))
            new.writestr("../do-not-execute.py",b"raise Exception('must never run')")
        with self.assertRaisesRegex(github.GitHubError,"bundle_archive"):
            github.load_local_bundle_archive(bad,hashlib.sha256(bad.read_bytes()).hexdigest(),self.bundle.bundle_id,self.folder/"bad-extra")
