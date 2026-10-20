# Python Rekor Monitor

A small command-line verifier for entries in the [Sigstore Rekor](https://rekor.sigstore.dev) transparency log. It can fetch the latest signed checkpoint, verify that a log entry is included in the log, verify the artifact signature attached to an entry, and check consistency between a previous checkpoint and the current log.

## Features
- Fetch and print the latest Rekor checkpoint.
- Verify an entry's inclusion proof and artifact signature.
- Verify consistency between an older checkpoint and the latest checkpoint.

### Verify consistency between checkpoints

```console
python main.py --consistency \
    --tree-id <tree-id> \
    --tree-size <previous-tree-size> \
    --root-hash <previous-root-hash>
```

## Repository contents

- `main.py` — command-line interface and Rekor API calls.
- `merkle_proof.py` — Merkle inclusion and consistency proof verification.
- `util.py` — certificate handling and artifact signature verification.
- `scripts/create_artifact.py` — creates a simple `artifact.md` containing a NetID.
- `artifact.md`, `artifact.bundle`, `artifact.sigstore.json` — sample artifact and signing material.
