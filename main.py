import argparse
import base64
import json
import urllib.request

from merkle_proof import (DefaultHasher, compute_leaf_hash,
                          verify_consistency, verify_inclusion)
from util import extract_public_key, verify_artifact_signature


REKOR_BASE_URL = "https://rekor.sigstore.dev"


def fetch_log_entry(log_index, debug=False):
    """Fetch a single log entry from Rekor for the given global log index."""
    url = f"{REKOR_BASE_URL}/api/v1/log/entries?logIndex={log_index}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req) as resp:
        raw = resp.read().decode("utf-8")
    entries = json.loads(raw)

    # The API returns a map keyed by the entry UUID; there should be one entry.
    entries_list = list(entries.values())
    if len(entries_list) != 1:
        raise ValueError(f"Expected exactly one log entry for index {log_index}, got {len(entries_list)}")

    return entries_list[0]


def get_log_body(log_index, debug=False):
    """Fetch the log entry and return its decoded body as a Python object."""
    entry = fetch_log_entry(log_index, debug)
    body = json.loads(base64.b64decode(entry["body"]).decode("utf-8"))
    return entry, body


def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"Invalid log index: {log_index}")

    entry, body = get_log_body(log_index, debug)
    if debug:
        print(json.dumps(body, indent=4))
    return entry, body


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"Invalid log index: {log_index}")

    entry, _ = get_log_body(log_index, debug)
    inclusion_proof = entry.get("verification", {}).get("inclusionProof")
    if inclusion_proof is None:
        raise ValueError(f"No inclusion proof found for log index {log_index}")

    if debug:
        print(json.dumps(inclusion_proof, indent=4))
    return inclusion_proof


def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"Invalid log index: {log_index}")
    if not artifact_filepath:
        raise ValueError("Artifact filepath must be provided")

    # 1. Fetch the entry and decode its body.
    entry, body = get_log_entry(log_index, debug)

    # 2. Extract signature and public key (certificate) from the body.
    spec = body["spec"]
    signature_b64 = spec["signature"]["content"]
    cert_pem = spec["signature"]["publicKey"]["content"]

    # The signature in the body is base64 encoded (without re-encoding the
    # DER bytes), so decode it back into raw bytes.
    signature = base64.b64decode(signature_b64)
    # The public key content is a PEM-encoded certificate.
    cert_der = base64.b64decode(cert_pem)

    public_key = extract_public_key(cert_der)

    # 3. Verify the signature in the log entry against the artifact.
    verify_artifact_signature(signature, public_key, artifact_filepath)

    # 4. Verify the inclusion proof.
    proof = get_verification_proof(log_index, debug)
    leaf_hash = compute_leaf_hash(entry["body"])

    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],       # index of the leaf within the tree
        proof["treeSize"],       # total number of leaves in the tree
        leaf_hash,
        proof["hashes"],         # hashes forming the Merkle proof
        proof["rootHash"],       # expected root hash
        debug,
    )
    print(f"Inclusion verified for log index {log_index}")


def get_latest_checkpoint(debug=False):
    # Fetch the latest checkpoint from rekor
    url = f"{REKOR_BASE_URL}/api/v1/log"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req) as resp:
        log_info = json.loads(resp.read().decode("utf-8"))

    checkpoint_text = log_info.get("signedTreeHead")
    if not checkpoint_text:
        raise ValueError("No signed tree head returned by Rekor")

    # The signed tree head is a text blob containing the checkpoint lines.
    lines = checkpoint_text.strip().split("\n")
    if len(lines) < 3:
        raise ValueError("Unexpected signed tree head format")

    checkpoint = {
        "treeID": log_info.get("treeID"),
        "treeSize": int(lines[1]),
        "rootHash": base64.b64decode(lines[2]).hex(),
    }

    if debug:
        with open("checkpoint.json", "w") as f:
            json.dump(checkpoint, f, indent=4)

    return checkpoint


def get_consistency_proof(first_size, last_size, tree_id, debug=False):
    """Fetch the consistency proof between two tree sizes from Rekor."""
    url = (f"{REKOR_BASE_URL}/api/v1/log/proof"
           f"?firstSize={first_size}&lastSize={last_size}&treeID={tree_id}")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req) as resp:
        proof = json.loads(resp.read().decode("utf-8"))

    if debug:
        print(json.dumps(proof, indent=4))
    return proof


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        raise ValueError("Previous checkpoint is empty")

    # verify that the prev checkpoint has the required fields
    required = ("treeID", "treeSize", "rootHash")
    for field in required:
        if field not in prev_checkpoint:
            raise ValueError(f"Previous checkpoint is missing field: {field}")

    # get latest checkpoint
    latest = get_latest_checkpoint(debug)

    old_size = prev_checkpoint["treeSize"]
    new_size = latest["treeSize"]

    # ensure the two checkpoints are actually distinct
    if old_size == new_size and prev_checkpoint["rootHash"] == latest["rootHash"]:
        raise ValueError(
            "Previous checkpoint is identical to the latest checkpoint; "
            "wait for more entries to be added before verifying consistency."
        )
    if old_size >= new_size:
        raise ValueError(
            f"Previous tree size ({old_size}) is not smaller than "
            f"latest tree size ({new_size})"
        )
    if prev_checkpoint["treeID"] != latest["treeID"]:
        raise ValueError(
            f"Tree ID mismatch: previous ({prev_checkpoint['treeID']}) vs "
            f"latest ({latest['treeID']})"
        )

    # obtain the consistency proof from Rekor
    proof = get_consistency_proof(
        old_size, new_size, latest["treeID"], debug
    )

    # verify consistency using the merkle proof library
    verify_consistency(
        DefaultHasher,
        old_size,                    # size of the older checkpoint
        new_size,                    # size of the latest checkpoint
        proof["hashes"],             # consistency proof hashes
        prev_checkpoint["rootHash"], # older root hash
        latest["rootHash"],          # latest root hash
    )

    print(f"Consistency verified between tree size {old_size} and {new_size}")


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
