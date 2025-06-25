#!/usr/bin/env python3

"""
Faithfully reproduces the smdpp certs contained in SGP.26_v1.5_Certificates_18_07_2024.zip
available at https://www.gsma.com/solutions-and-impact/technologies/esim/gsma_resources/sgp-26-test-certificate-definition-v1-5/
Only usable for testing, it obviously uses a different CI key.
"""

import os
import binascii
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Custom OIDs used in certificates
OID_CERTIFICATE_POLICIES_CI = "2.23.146.1.2.1.0"  # CI cert policy
OID_CERTIFICATE_POLICIES_TLS = "2.23.146.1.2.1.3"  # DPtls cert policy
OID_CERTIFICATE_POLICIES_AUTH = "2.23.146.1.2.1.4"  # DPauth cert policy
OID_CERTIFICATE_POLICIES_PB = "2.23.146.1.2.1.5"  # DPpb cert policy

# Subject Alternative Name OIDs
OID_CI_RID = "2.999.1"  # CI Registered ID
OID_DP_RID = "2.999.10"  # DP+ Registered ID
OID_DP2_RID = "2.999.12"  # DP+2 Registered ID
OID_DP4_RID = "2.999.14"  # DP+4 Registered ID
OID_DP8_RID = "2.999.18"  # DP+8 Registered ID


class SimplifiedCertificateGenerator:
    def __init__(self):
        self.backend = default_backend()
        # Store generated CI keys to sign other certs
        self.ci_certs = {}  # {"BRP": cert, "NIST": cert}
        self.ci_keys = {}   # {"BRP": key, "NIST": key}

    def get_curve(self, curve_type):
        """Get the appropriate curve object."""
        if curve_type == "BRP":
            return ec.BrainpoolP256R1()
        else:
            return ec.SECP256R1()

    def generate_key_pair(self, curve):
        """Generate a new EC key pair."""
        private_key = ec.generate_private_key(curve, self.backend)
        return private_key

    def load_private_key_from_hex(self, hex_key, curve):
        """Load EC private key from hex string."""
        key_bytes = binascii.unhexlify(hex_key.replace(":", "").replace(" ", "").replace("\n", ""))
        key_int = int.from_bytes(key_bytes, 'big')
        return ec.derive_private_key(key_int, curve, self.backend)

    def generate_ci_cert(self, curve_type):
        """Generate CI certificate for either BRP or NIST curve."""
        curve = self.get_curve(curve_type)
        private_key = self.generate_key_pair(curve)

        # Build subject and issuer (self-signed) - same for both
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CI"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TESTCERT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSPTEST"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        ])

        # Build certificate - all parameters same for both
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(datetime(2020, 4, 1, 8, 27, 51))
        builder = builder.not_valid_after(datetime(2055, 4, 1, 8, 27, 51))
        builder = builder.serial_number(0xb874f3abfa6c44d3)
        builder = builder.public_key(private_key.public_key())

        # Add extensions - all same for both
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier(OID_CERTIFICATE_POLICIES_CI),
                    policy_qualifiers=None
                )
            ]),
            critical=True
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.RegisteredID(x509.ObjectIdentifier(OID_CI_RID))
            ]),
            critical=False
        )

        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-A.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                ),
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-B.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )

        certificate = builder.sign(private_key, hashes.SHA256(), self.backend)

        self.ci_keys[curve_type] = private_key
        self.ci_certs[curve_type] = certificate

        return certificate, private_key

    def generate_dp_cert(self, curve_type, subject_cn, serial, key_hex,
                        cert_policy_oid, rid_oid, validity_start, validity_end):
        """Generate a DP certificate signed by CI - works for both BRP and NIST."""
        curve = self.get_curve(curve_type)
        private_key = self.load_private_key_from_hex(key_hex, curve)

        ci_cert = self.ci_certs[curve_type]
        ci_key = self.ci_keys[curve_type]

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ci_cert.subject)
        builder = builder.not_valid_before(validity_start)
        builder = builder.not_valid_after(validity_end)
        builder = builder.serial_number(serial)
        builder = builder.public_key(private_key.public_key())

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ci_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.RegisteredID(x509.ObjectIdentifier(rid_oid))
            ]),
            critical=False
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier(cert_policy_oid),
                    policy_qualifiers=None
                )
            ]),
            critical=True
        )

        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-A.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                ),
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-B.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )

        certificate = builder.sign(ci_key, hashes.SHA256(), self.backend)

        return certificate, private_key

    def generate_tls_cert(self, curve_type, subject_cn, dns_name, serial, key_hex,
                         rid_oid, validity_start, validity_end):
        """Generate a TLS certificate signed by CI."""
        curve = self.get_curve(curve_type)
        private_key = self.load_private_key_from_hex(key_hex, curve)

        ci_cert = self.ci_certs[curve_type]
        ci_key = self.ci_keys[curve_type]

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ci_cert.subject)
        builder = builder.not_valid_before(validity_start)
        builder = builder.not_valid_after(validity_end)
        builder = builder.serial_number(serial)
        builder = builder.public_key(private_key.public_key())

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=True
        )

        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier(OID_CERTIFICATE_POLICIES_TLS),
                    policy_qualifiers=None
                )
            ]),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ci_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(dns_name),
                x509.RegisteredID(x509.ObjectIdentifier(rid_oid))
            ]),
            critical=False
        )

        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-A.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                ),
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-B.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )

        certificate = builder.sign(ci_key, hashes.SHA256(), self.backend)

        return certificate, private_key

    def generate_eum_cert(self, curve_type, key_hex):
        """Generate EUM certificate signed by CI."""
        curve = self.get_curve(curve_type)
        private_key = self.load_private_key_from_hex(key_hex, curve)

        ci_cert = self.ci_certs[curve_type]
        ci_key = self.ci_keys[curve_type]

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
            x509.NameAttribute(NameOID.COMMON_NAME, "EUM Test"),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ci_cert.subject)
        builder = builder.not_valid_before(datetime(2020, 4, 1, 9, 28, 37))
        builder = builder.not_valid_after(datetime(2054, 3, 24, 9, 28, 37))
        builder = builder.serial_number(0x12345678)
        builder = builder.public_key(private_key.public_key())

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ci_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.23.146.1.2.1.2"),  # EUM policy
                    policy_qualifiers=None
                )
            ]),
            critical=True
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.RegisteredID(x509.ObjectIdentifier("2.999.5"))
            ]),
            critical=False
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )

        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://ci.test.example.com/CRL-B.crl")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None
                )
            ]),
            critical=False
        )

        # Name Constraints
        constrained_name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "89049032"),
        ])

        name_constraints = x509.NameConstraints(
            permitted_subtrees=[
                x509.DirectoryName(constrained_name)
            ],
            excluded_subtrees=None
        )

        builder = builder.add_extension(
            name_constraints,
            critical=True
        )

        certificate = builder.sign(ci_key, hashes.SHA256(), self.backend)

        return certificate, private_key

    def generate_euicc_cert(self, curve_type, eum_cert, eum_key, key_hex):
        """Generate eUICC certificate signed by EUM."""
        curve = self.get_curve(curve_type)
        private_key = self.load_private_key_from_hex(key_hex, curve)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "89049032123451234512345678901235"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test eUICC"),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(eum_cert.subject)
        builder = builder.not_valid_before(datetime(2020, 4, 1, 9, 48, 58))
        builder = builder.not_valid_after(datetime(7496, 1, 24, 9, 48, 58))
        builder = builder.serial_number(0x0200000000000001)
        builder = builder.public_key(private_key.public_key())

        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(eum_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        builder = builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.23.146.1.2.1.1"),  # eUICC policy
                    policy_qualifiers=None
                )
            ]),
            critical=True
        )

        certificate = builder.sign(eum_key, hashes.SHA256(), self.backend)

        return certificate, private_key

    def save_cert_and_key(self, cert, key, cert_path_der, cert_path_pem, key_path_sk, key_path_pk):
        """Save certificate and key in various formats."""
        # Create directories if needed
        os.makedirs(os.path.dirname(cert_path_der), exist_ok=True)

        with open(cert_path_der, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        if cert_path_pem:
            with open(cert_path_pem, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

        if key and key_path_sk:
            with open(key_path_sk, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        if key and key_path_pk:
            with open(key_path_pk, "wb") as f:
                f.write(key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))


def main():
    gen = SimplifiedCertificateGenerator()

    output_dir = "smdpp-data/generated"
    os.makedirs(output_dir, exist_ok=True)

    print("=== Generating CI Certificates ===")

    for curve_type in ["BRP", "NIST"]:
        ci_cert, ci_key = gen.generate_ci_cert(curve_type)
        suffix = "_ECDSA_BRP" if curve_type == "BRP" else "_ECDSA_NIST"
        gen.save_cert_and_key(
            ci_cert, ci_key,
            f"{output_dir}/CertificateIssuer/CERT_CI{suffix}.der",
            f"{output_dir}/CertificateIssuer/CERT_CI{suffix}.pem",
            None, None
        )
        print(f"Generated CI {curve_type} certificate")

    print("\n=== Generating DPauth Certificates ===")

    dpauth_configs = [
        ("BRP", "TEST SM-DP+", 256, "93:fb:33:d0:58:4f:34:9b:07:f8:b5:d2:af:93:d7:c3:e3:54:b3:49:a3:b9:13:50:2e:6a:bc:07:0e:4d:49:29", OID_DP_RID, "DPauth"),
        ("NIST", "TEST SM-DP+", 256, "0a:7c:c1:c2:44:e6:0c:52:cd:5b:78:07:ab:8c:36:0c:26:52:46:01:50:7d:ca:bc:5d:d5:98:b5:a6:16:d5:d5", OID_DP_RID, "DPauth"),
        ("BRP", "TEST SM-DP+2", 512, "0c:17:35:5c:01:1d:0f:e8:d7:da:dd:63:f1:97:85:cf:6c:51:cb:cd:46:6a:e8:8b:e8:f8:1b:c1:05:88:46:f6", OID_DP2_RID, "DP2auth"),
        ("NIST", "TEST SM-DP+2", 512, "9c:32:a0:95:d4:88:42:d9:ff:a4:04:f7:12:51:2a:a2:c5:42:5a:1a:26:38:6a:b6:a1:45:d5:81:1e:03:91:41", OID_DP2_RID, "DP2auth"),
    ]

    for curve_type, cn, serial, key_hex, rid_oid, name_prefix in dpauth_configs:
        cert, key = gen.generate_dp_cert(
            curve_type, cn, serial, key_hex,
            OID_CERTIFICATE_POLICIES_AUTH, rid_oid,
            datetime(2020, 4, 1, 8, 31, 30),
            datetime(2030, 3, 30, 8, 31, 30)
        )
        suffix = "_ECDSA_BRP" if curve_type == "BRP" else "_ECDSA_NIST"
        gen.save_cert_and_key(
            cert, key,
            f"{output_dir}/DPauth/CERT_S_SM_{name_prefix}{suffix}.der",
            None,
            f"{output_dir}/DPauth/SK_S_SM_{name_prefix}{suffix}.pem",
            f"{output_dir}/DPauth/PK_S_SM_{name_prefix}{suffix}.pem"
        )
        print(f"Generated {name_prefix} {curve_type} certificate")

    print("\n=== Generating DPpb Certificates ===")

    dppb_configs = [
        ("BRP", "TEST SM-DP+", 257, "75:ff:32:2f:41:66:16:da:e1:a4:84:ef:71:d4:87:4f:b0:df:32:95:fd:35:c2:cb:a4:89:fb:b2:bb:9c:7b:f6", OID_DP_RID, "DPpb"),
        ("NIST", "TEST SM-DP+", 257, "dc:d6:94:b7:78:95:7e:8e:9a:dd:bd:d9:44:33:e9:ef:8f:73:d1:1e:49:1c:48:d4:25:a3:8a:94:91:bd:3b:ed", OID_DP_RID, "DPpb"),
        ("BRP", "TEST SM-DP+2", 513, "9c:ae:2e:1a:56:07:a9:d5:78:38:2e:ee:93:2e:25:1f:52:30:4f:86:ee:b1:f1:70:8c:db:d3:c0:7b:e2:cd:3d", OID_DP2_RID, "DP2pb"),
        ("NIST", "TEST SM-DP+2", 513, "66:93:11:49:63:9d:ba:ac:1d:c3:d3:06:c5:8b:d2:df:d2:2f:73:bf:63:ac:86:31:98:32:90:b5:7f:90:93:45", OID_DP2_RID, "DP2pb"),
    ]

    for curve_type, cn, serial, key_hex, rid_oid, name_prefix in dppb_configs:
        cert, key = gen.generate_dp_cert(
            curve_type, cn, serial, key_hex,
            OID_CERTIFICATE_POLICIES_PB, rid_oid,
            datetime(2020, 4, 1, 8, 34, 46),
            datetime(2030, 3, 30, 8, 34, 46)
        )
        suffix = "_ECDSA_BRP" if curve_type == "BRP" else "_ECDSA_NIST"
        gen.save_cert_and_key(
            cert, key,
            f"{output_dir}/DPpb/CERT_S_SM_{name_prefix}{suffix}.der",
            None,
            f"{output_dir}/DPpb/SK_S_SM_{name_prefix}{suffix}.pem",
            f"{output_dir}/DPpb/PK_S_SM_{name_prefix}{suffix}.pem"
        )
        print(f"Generated {name_prefix} {curve_type} certificate")

    print("\n=== Generating DPtls Certificates ===")

    dptls_configs = [
        ("BRP", "testsmdpplus1.example.com", "testsmdpplus1.example.com", 9, "3f:67:15:28:02:b3:f4:c7:fa:e6:79:58:55:f6:82:54:1e:45:e3:5e:ff:f4:e8:a0:55:65:a0:f1:91:2a:78:2e", OID_DP_RID, "DP_TLS_BRP"),
        ("NIST", "testsmdpplus1.example.com", "testsmdpplus1.example.com", 9, "a0:3e:7c:e4:55:04:74:be:a4:b7:a8:73:99:ce:5a:8c:9f:66:1b:68:0f:94:01:39:ff:f8:4e:9d:ec:6a:4d:8c", OID_DP_RID, "DP_TLS_NIST"),
        ("NIST", "testsmdpplus2.example.com", "testsmdpplus2.example.com", 12, "4e:65:61:c6:40:88:f6:69:90:7a:db:e3:94:b1:1a:84:24:2e:03:3a:82:a8:84:02:31:63:6d:c9:1b:4e:e3:f5", OID_DP2_RID, "DP2_TLS"),
        ("NIST", "testsmdpplus4.example.com", "testsmdpplus4.example.com", 14, "f2:65:9d:2f:52:8f:4b:11:37:40:d5:8a:0d:2a:f3:eb:2b:48:e1:22:c2:b6:0a:6a:f6:fc:96:ad:86:be:6f:a4", OID_DP4_RID, "DP4_TLS"),
        ("NIST", "testsmdpplus8.example.com", "testsmdpplus8.example.com", 18, "ff:6e:4a:50:9b:ad:db:38:10:88:31:c2:3c:cc:2d:44:30:7a:f2:81:e9:25:96:7f:8c:df:1d:95:54:a0:28:8d", OID_DP8_RID, "DP8_TLS"),
    ]

    for curve_type, cn, dns, serial, key_hex, rid_oid, name_prefix in dptls_configs:
        cert, key = gen.generate_tls_cert(
            curve_type, cn, dns, serial, key_hex, rid_oid,
            datetime(2024, 7, 9, 15, 29, 36),
            datetime(2025, 8, 11, 15, 29, 36)
        )
        gen.save_cert_and_key(
            cert, key,
            f"{output_dir}/DPtls/CERT_S_SM_{name_prefix}.der",
            None,
            f"{output_dir}/DPtls/SK_S_SM_{name_prefix.replace('_BRP', '_BRP').replace('_NIST', '_NIST')}.pem",
            f"{output_dir}/DPtls/PK_S_SM_{name_prefix.replace('_BRP', '_BRP').replace('_NIST', '_NIST')}.pem"
        )
        print(f"Generated {name_prefix} certificate")

    print("\n=== Generating EUM Certificates ===")

    eum_configs = [
        ("BRP", "12:9b:0a:b1:3f:17:e1:4a:40:b6:fa:4e:d8:23:e0:cf:46:5b:7b:3d:73:24:05:e6:29:5d:3b:23:b0:45:c9:9a"),
        ("NIST", "25:e6:75:77:28:e1:e9:51:13:51:9c:dc:34:55:5c:29:ba:ed:23:77:3a:c5:af:dd:dc:da:d9:84:89:8a:52:f0"),
    ]

    eum_certs = {}
    eum_keys = {}

    for curve_type, key_hex in eum_configs:
        cert, key = gen.generate_eum_cert(curve_type, key_hex)
        eum_certs[curve_type] = cert
        eum_keys[curve_type] = key
        suffix = "_ECDSA_BRP" if curve_type == "BRP" else "_ECDSA_NIST"
        gen.save_cert_and_key(
            cert, key,
            f"{output_dir}/EUM/CERT_EUM{suffix}.der",
            None,
            f"{output_dir}/EUM/SK_EUM{suffix}.pem",
            f"{output_dir}/EUM/PK_EUM{suffix}.pem"
        )
        print(f"Generated EUM {curve_type} certificate")

    print("\n=== Generating eUICC Certificates ===")

    euicc_configs = [
        ("BRP", "8d:c3:47:a7:6d:b7:bd:d6:22:2d:d7:5e:a1:a1:68:8a:ca:81:1e:4c:bc:6a:7f:6a:ef:a4:b2:64:19:62:0b:90"),
        ("NIST", "11:e1:54:67:dc:19:4f:33:71:83:e4:60:c9:f6:32:60:09:1e:12:e8:10:26:cd:65:61:e1:7c:6d:85:39:cc:9c"),
    ]

    for curve_type, key_hex in euicc_configs:
        cert, key = gen.generate_euicc_cert(curve_type, eum_certs[curve_type], eum_keys[curve_type], key_hex)
        suffix = "_ECDSA_BRP" if curve_type == "BRP" else "_ECDSA_NIST"
        gen.save_cert_and_key(
            cert, key,
            f"{output_dir}/eUICC/CERT_EUICC{suffix}.der",
            None,
            f"{output_dir}/eUICC/SK_EUICC{suffix}.pem",
            f"{output_dir}/eUICC/PK_EUICC{suffix}.pem"
        )
        print(f"Generated eUICC {curve_type} certificate")

    print("\n=== Certificate generation complete! ===")
    print(f"All certificates saved to: {output_dir}/")

if __name__ == "__main__":
    main()