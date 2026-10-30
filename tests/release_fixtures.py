"""Synthetic signatures for testing the public-key release verifier only."""
from release_tools.bundle import canonical_json
from release_tools import trust


def sign_test_approval(bundle, key, key_id):
    unsigned = {"schema": 1, "key_id": key_id, "payload": trust._payload(bundle)}
    import base64
    return {**unsigned, "signature": base64.b64encode(
        key.sign(trust.DOMAIN + canonical_json(unsigned))).decode("ascii")}
