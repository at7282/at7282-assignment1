import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from util import extract_public_key, verify_artifact_signature


def _make_certificate():
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rekor-monitor-test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate.public_bytes(serialization.Encoding.PEM)


def _sign(private_key, data):
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def test_extract_public_key_returns_pem_public_key():
    _, cert_pem = _make_certificate()

    public_key_pem = extract_public_key(cert_pem)

    assert b"BEGIN PUBLIC KEY" in public_key_pem
    loaded = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(loaded, ec.EllipticCurvePublicKey)


def test_verify_artifact_signature_accepts_valid_signature(tmp_path):
    private_key, cert_pem = _make_certificate()
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"at7282\n")
    signature = _sign(private_key, artifact.read_bytes())
    public_key = extract_public_key(cert_pem)

    assert verify_artifact_signature(signature, public_key, str(artifact)) is True


def test_verify_artifact_signature_rejects_modified_artifact(tmp_path):
    private_key, cert_pem = _make_certificate()
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"at7282\n")
    signature = _sign(private_key, artifact.read_bytes())
    artifact.write_bytes(b"tampered\n")
    public_key = extract_public_key(cert_pem)

    with pytest.raises(ValueError, match="Artifact signature is invalid"):
        verify_artifact_signature(signature, public_key, str(artifact))


def test_extract_public_key_rejects_invalid_pem():
    with pytest.raises(ValueError):
        extract_public_key(b"not a certificate")


def test_verify_artifact_signature_missing_file(tmp_path):
    private_key, cert_pem = _make_certificate()
    signature = _sign(private_key, b"data")
    public_key = extract_public_key(cert_pem)

    with pytest.raises(FileNotFoundError):
        verify_artifact_signature(signature, public_key, str(tmp_path / "missing.md"))
