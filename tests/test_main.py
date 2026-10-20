import base64
import json
import sys
import urllib.error

import pytest

import main


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_fetch_json_success(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["accept"] = request.get_header("Accept")
        return FakeResponse(b'{"proof": [1, 2, 3]}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    payload = main.fetch_json("https://rekor.example/api/v1/log")

    assert payload == {"proof": [1, 2, 3]}
    assert captured == {
        "url": "https://rekor.example/api/v1/log",
        "timeout": main.REQUEST_TIMEOUT_SECONDS,
        "accept": "application/json",
    }


def test_fetch_json_rejects_non_https():
    with pytest.raises(main.RekorError, match="Refusing to fetch non-HTTPS URL"):
        main.fetch_json("http://rekor.example/api/v1/log")


def test_fetch_json_reports_http_errors(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 500, "Server Error", None, None)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(main.RekorError, match="HTTP 500"):
        main.fetch_json("https://rekor.example/api/v1/log")


def test_fetch_json_reports_url_error_timeout(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(main.RekorError, match="timed out"):
        main.fetch_json("https://rekor.example/api/v1/log")


def test_fetch_json_reports_url_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(main.RekorError, match="Could not reach Rekor"):
        main.fetch_json("https://rekor.example/api/v1/log")


def test_fetch_json_reports_builtin_timeout(monkeypatch):
    def fake_urlopen(request, timeout):
        raise TimeoutError("slow")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(main.RekorError, match="timed out"):
        main.fetch_json("https://rekor.example/api/v1/log")


def test_fetch_json_reports_invalid_json(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse(b"not-json"),
    )

    with pytest.raises(main.RekorError, match="invalid JSON"):
        main.fetch_json("https://rekor.example/api/v1/log")


def test_fetch_log_entry_returns_single_entry(monkeypatch):
    entry = {"body": "abc"}
    monkeypatch.setattr(main, "fetch_json", lambda url: {"uuid": entry})

    assert main.fetch_log_entry(7) == entry


def test_fetch_log_entry_rejects_unexpected_entry_count(monkeypatch):
    monkeypatch.setattr(main, "fetch_json", lambda url: {})

    with pytest.raises(ValueError, match="Expected exactly one log entry"):
        main.fetch_log_entry(7)


def test_get_log_body_decodes_entry(monkeypatch):
    body = {"kind": "hashedrekord", "apiVersion": "0.0.1"}
    entry = {"body": base64.b64encode(json.dumps(body).encode("utf-8")).decode("utf-8")}
    monkeypatch.setattr(main, "fetch_log_entry", lambda index, debug=False: entry)

    returned_entry, returned_body = main.get_log_body(3)

    assert returned_entry is entry
    assert returned_body == body


@pytest.mark.parametrize("index", [-1, "1", 1.5])
def test_get_log_entry_rejects_invalid_index(index):
    with pytest.raises(ValueError, match="Invalid log index"):
        main.get_log_entry(index)


def test_get_log_entry_prints_debug_body(monkeypatch, capsys):
    body = {"kind": "hashedrekord"}
    monkeypatch.setattr(
        main,
        "get_log_body",
        lambda index, debug=False: ({"body": "x"}, body),
    )

    entry, returned_body = main.get_log_entry(0, debug=True)

    assert entry == {"body": "x"}
    assert returned_body == body
    assert '"kind": "hashedrekord"' in capsys.readouterr().out


@pytest.mark.parametrize("index", [-1, "1"])
def test_get_verification_proof_rejects_invalid_index(index):
    with pytest.raises(ValueError, match="Invalid log index"):
        main.get_verification_proof(index)


def test_get_verification_proof_returns_proof(monkeypatch):
    proof = {"logIndex": 4, "treeSize": 10, "hashes": [], "rootHash": "00"}
    monkeypatch.setattr(
        main,
        "get_log_body",
        lambda index, debug=False: ({"verification": {"inclusionProof": proof}}, {}),
    )

    assert main.get_verification_proof(4) == proof


def test_get_verification_proof_requires_proof(monkeypatch):
    monkeypatch.setattr(
        main,
        "get_log_body",
        lambda index, debug=False: ({"verification": {}}, {}),
    )

    with pytest.raises(ValueError, match="No inclusion proof"):
        main.get_verification_proof(4)


def test_inclusion_verifies_signature_and_merkle_proof(monkeypatch, tmp_path, capsys):
    artifact = tmp_path / "artifact.md"
    artifact.write_text("at7282\n", encoding="utf-8")

    signature = b"signature-bytes"
    certificate = b"certificate-pem"
    body = {
        "spec": {
            "signature": {
                "content": base64.b64encode(signature).decode("utf-8"),
                "publicKey": {
                    "content": base64.b64encode(certificate).decode("utf-8"),
                },
            }
        }
    }
    entry = {"body": base64.b64encode(b"leaf-body").decode("utf-8")}
    proof = {
        "logIndex": 7,
        "treeSize": 20,
        "hashes": ["aa", "bb"],
        "rootHash": "cc",
    }
    calls = {}

    monkeypatch.setattr(
        main,
        "get_log_entry",
        lambda index, debug=False: (entry, body),
    )
    monkeypatch.setattr(
        main,
        "get_verification_proof",
        lambda index, debug=False: proof,
    )
    monkeypatch.setattr(main, "extract_public_key", lambda cert: b"public-key")
    monkeypatch.setattr(
        main,
        "verify_artifact_signature",
        lambda sig, key, path: calls.update(signature=sig, key=key, path=path),
    )
    monkeypatch.setattr(main, "compute_leaf_hash", lambda raw: "leaf-hash")
    monkeypatch.setattr(
        main,
        "verify_inclusion",
        lambda *args: calls.setdefault("inclusion", args),
    )

    main.inclusion(7, str(artifact))

    assert calls["signature"] == signature
    assert calls["key"] == b"public-key"
    assert calls["path"] == str(artifact)
    assert calls["inclusion"] == (
        main.DefaultHasher,
        7,
        20,
        "leaf-hash",
        ["aa", "bb"],
        "cc",
        False,
    )
    assert "Inclusion verified for log index 7" in capsys.readouterr().out


@pytest.mark.parametrize("index", [-1, "1"])
def test_inclusion_rejects_invalid_index(index):
    with pytest.raises(ValueError, match="Invalid log index"):
        main.inclusion(index, "artifact.md")


def test_inclusion_requires_artifact_path():
    with pytest.raises(ValueError, match="Artifact filepath must be provided"):
        main.inclusion(1, "")


def test_get_latest_checkpoint(monkeypatch):
    root_hex = "ab" * 32
    root_b64 = base64.b64encode(bytes.fromhex(root_hex)).decode("utf-8")
    signed_tree_head = (
        f"rekor.sigstore.dev - 1193050959916656506\n42\n{root_b64}\n\n\u2014 rekor.sigstore.dev"
    )
    monkeypatch.setattr(
        main,
        "fetch_json",
        lambda url: {"signedTreeHead": signed_tree_head, "treeID": "1234"},
    )

    checkpoint = main.get_latest_checkpoint()

    assert checkpoint == {"treeID": "1234", "treeSize": 42, "rootHash": root_hex}


def test_get_latest_checkpoint_requires_signed_tree_head(monkeypatch):
    monkeypatch.setattr(main, "fetch_json", lambda url: {"signedTreeHead": ""})

    with pytest.raises(ValueError, match="No signed tree head"):
        main.get_latest_checkpoint()


def test_get_latest_checkpoint_rejects_malformed_tree_head(monkeypatch):
    monkeypatch.setattr(
        main,
        "fetch_json",
        lambda url: {"signedTreeHead": "only\ntwo lines"},
    )

    with pytest.raises(ValueError, match="Unexpected signed tree head format"):
        main.get_latest_checkpoint()


def test_get_consistency_proof_requests_expected_url(monkeypatch):
    captured = {}
    proof = {"hashes": ["aa"]}

    def fake_fetch_json(url):
        captured["url"] = url
        return proof

    monkeypatch.setattr(main, "fetch_json", fake_fetch_json)

    assert main.get_consistency_proof(10, 20, "tree-id") == proof
    assert "firstSize=10" in captured["url"]
    assert "lastSize=20" in captured["url"]
    assert "treeID=tree-id" in captured["url"]


def test_consistency_requires_previous_checkpoint():
    with pytest.raises(ValueError, match="Previous checkpoint is empty"):
        main.consistency({})


def test_consistency_requires_all_checkpoint_fields():
    with pytest.raises(ValueError, match="missing field: rootHash"):
        main.consistency({"treeID": "t", "treeSize": 1})


def test_consistency_rejects_identical_checkpoint(monkeypatch):
    checkpoint = {"treeID": "t", "treeSize": 5, "rootHash": "aa"}
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: checkpoint)

    with pytest.raises(ValueError, match="identical to the latest checkpoint"):
        main.consistency(checkpoint)


def test_consistency_rejects_latest_tree_not_larger(monkeypatch):
    previous = {"treeID": "t", "treeSize": 5, "rootHash": "aa"}
    latest = {"treeID": "t", "treeSize": 5, "rootHash": "bb"}
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: latest)

    with pytest.raises(ValueError, match="is not smaller than latest tree size"):
        main.consistency(previous)


def test_consistency_rejects_tree_id_mismatch(monkeypatch):
    previous = {"treeID": "old", "treeSize": 5, "rootHash": "aa"}
    latest = {"treeID": "new", "treeSize": 6, "rootHash": "bb"}
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: latest)

    with pytest.raises(ValueError, match="Tree ID mismatch"):
        main.consistency(previous)


def test_consistency_verifies_proof(monkeypatch, capsys):
    previous = {"treeID": "t", "treeSize": 5, "rootHash": "aa"}
    latest = {"treeID": "t", "treeSize": 6, "rootHash": "bb"}
    calls = {}

    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: latest)
    monkeypatch.setattr(
        main,
        "get_consistency_proof",
        lambda first, last, tree_id, debug=False: {"hashes": ["cc"]},
    )
    monkeypatch.setattr(
        main,
        "verify_consistency",
        lambda *args: calls.setdefault("args", args),
    )

    main.consistency(previous)

    assert calls["args"] == (main.DefaultHasher, 5, 6, ["cc"], "aa", "bb")
    assert "Consistency verified between tree size 5 and 6" in capsys.readouterr().out


def test_main_checkpoint(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--checkpoint"])
    monkeypatch.setattr(
        main,
        "get_latest_checkpoint",
        lambda debug=False: {"treeID": "t", "treeSize": 1, "rootHash": "aa"},
    )

    main.main()

    assert '"treeID": "t"' in capsys.readouterr().out


def test_main_debug_mode(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--debug", "--checkpoint"])
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: {})

    main.main()

    assert "enabled debug mode" in capsys.readouterr().out


def test_main_inclusion(monkeypatch):
    captured = {}
    monkeypatch.setattr(sys, "argv", ["main.py", "--inclusion", "9", "--artifact", "a.md"])
    monkeypatch.setattr(
        main,
        "inclusion",
        lambda index, artifact, debug=False: captured.update(
            index=index, artifact=artifact, debug=debug
        ),
    )

    main.main()

    assert captured == {"index": 9, "artifact": "a.md", "debug": False}


@pytest.mark.parametrize(
    ("argv", "expected_message"),
    [
        (["main.py", "--consistency"], "please specify tree id"),
        (["main.py", "--consistency", "--tree-id", "t"], "please specify tree size"),
        (
            ["main.py", "--consistency", "--tree-id", "t", "--tree-size", "1"],
            "please specify root hash",
        ),
    ],
)
def test_main_consistency_requires_previous_checkpoint_arguments(
    monkeypatch, capsys, argv, expected_message
):
    monkeypatch.setattr(sys, "argv", argv)

    main.main()

    assert expected_message in capsys.readouterr().out


def test_main_consistency_builds_previous_checkpoint(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--consistency",
            "--tree-id",
            "t",
            "--tree-size",
            "3",
            "--root-hash",
            "aa",
        ],
    )
    monkeypatch.setattr(
        main,
        "consistency",
        lambda checkpoint, debug=False: captured.update(checkpoint=checkpoint, debug=debug),
    )

    main.main()

    assert captured == {
        "checkpoint": {"treeID": "t", "treeSize": 3, "rootHash": "aa"},
        "debug": False,
    }
