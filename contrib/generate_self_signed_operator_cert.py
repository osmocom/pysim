#!/usr/bin/env python3

"""
Generate a self-signed operator certificate for ES2+ testing.
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

SELFPATH=os.path.abspath(os.path.dirname(__file__))

def generate_self_signed_operator_cert(operator_name, output_dir):
    """Generate a self-signed operator certificate."""

    # Generate key pair (using NIST P-256 curve)
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Build subject (and issuer, since self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{operator_name} ES2+ Client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, operator_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "eSIM Operations"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.now() - timedelta(days=1))
    builder = builder.not_valid_after(datetime.now() + timedelta(days=365))  # 1 year
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())

    # Add extensions
    # Subject Key Identifier - this is what SM-DP+ will use to identify the operator
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )

    # Authority Key Identifier (points to itself since self-signed)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False
    )

    # Basic Constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    # Key Usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    # Extended Key Usage - Client Authentication
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True
    )

    # Sign the certificate
    certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Save certificate in PEM format
    cert_pem_path = os.path.join(output_dir, f"{operator_name}_selfsigned.pem")
    with open(cert_pem_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    # Save private key in PEM format
    key_pem_path = os.path.join(output_dir, f"{operator_name}_selfsigned_key.pem")
    with open(key_pem_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save combined cert+key for easy use with es2p_client.py
    combined_path = os.path.join(output_dir, f"{operator_name}_selfsigned_combined.pem")
    with open(combined_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    ski_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    ski_hex = ski_ext.value.key_identifier.hex()
    ski_formatted = ':'.join(ski_hex[i:i+2].upper() for i in range(0, len(ski_hex), 2))

    print(f"Generated self-signed certificate for {operator_name}:")
    print(f"  Certificate: {cert_pem_path}")
    print(f"  Private Key: {key_pem_path}")
    print(f"  Combined (for es2p_client.py): {combined_path}")
    print(f"  Subject Key Identifier (SKI): {ski_formatted}")
    print("\nThis SKI can be added to the SM-DP+ trusted operators list.")

    return combined_path, ski_formatted


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate self-signed operator certificate for ES2+ testing")
    parser.add_argument("--operator", default="TEST_OPERATOR", help="Operator name")
    parser.add_argument("--output-dir", default=os.path.abspath(SELFPATH+"/../smdpp-data/certs/SelfSignedOperators"), help="Output directory")

    args = parser.parse_args()

    generate_self_signed_operator_cert(args.operator, args.output_dir)