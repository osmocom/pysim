"""X.509 certificate verification exceptions for GSMA eSIM."""

class VerifyError(Exception):
    """Base class for certificate verification errors."""
    pass


class MissingIntermediateCert(VerifyError):
    """Raised when an intermediate certificate in the chain cannot be found."""
    def __init__(self, auth_key_id: str):
        self.auth_key_id = auth_key_id
        super().__init__(f'Could not find intermediate certificate for AuthKeyId {auth_key_id}')


class CertificateRevoked(VerifyError):
    """Raised when a certificate is found in the CRL."""
    def __init__(self, cert_serial: str = None):
        self.cert_serial = cert_serial
        msg = 'Certificate is present in CRL, verification failed'
        if cert_serial:
            msg += f' (serial: {cert_serial})'
        super().__init__(msg)


class MaxDepthExceeded(VerifyError):
    """Raised when certificate chain depth exceeds the maximum allowed."""
    def __init__(self, max_depth: int, actual_depth: int):
        self.max_depth = max_depth
        self.actual_depth = actual_depth
        super().__init__(f'Maximum depth {max_depth} exceeded while verifying certificate chain (actual: {actual_depth})')


class SignatureVerification(VerifyError):
    """Raised when certificate signature verification fails."""
    def __init__(self, cert_subject: str = None, signer_subject: str = None):
        self.cert_subject = cert_subject
        self.signer_subject = signer_subject
        msg = 'Certificate signature verification failed'
        if cert_subject and signer_subject:
            msg += f': {cert_subject} not signed by {signer_subject}'
        super().__init__(msg)


class InvalidCertificate(VerifyError):
    """Raised when a certificate is invalid (missing required fields, wrong type, etc)."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f'Invalid certificate: {reason}')


class CertificateExpired(VerifyError):
    """Raised when a certificate has expired."""
    def __init__(self, cert_subject: str = None):
        self.cert_subject = cert_subject
        msg = 'Certificate has expired'
        if cert_subject:
            msg += f': {cert_subject}'
        super().__init__(msg)