from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption, load_pem_private_key
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.backends import default_backend
import datetime

# Generate a private key for the user
user_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Generate a private key for the CA
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Create a CSR (Certificate Signing Request)
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mydomain.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName(u"www.mydomain.com"),
        x509.DNSName(u"subdomain.mydomain.com"),
    ]),
    critical=False,
).sign(user_key, hashes.SHA256(), default_backend())

# CA signs the CSR and creates a certificate
one_day = datetime.timedelta(1, 0, 0)
certificate = x509.CertificateBuilder().subject_name(
    csr.subject
).issuer_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
    ])
).public_key(
    csr.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.today()
).not_valid_after(
    datetime.datetime.today() + one_day
).add_extension(
    x509.SubjectAlternativeName(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
    critical=False,
).sign(ca_key, hashes.SHA256(), default_backend())

# Output the certificate
cert_pem = certificate.public_bytes(Encoding.PEM)
print(cert_pem.decode())