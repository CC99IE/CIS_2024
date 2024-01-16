import subprocess
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

CA_NAME = 'localCA'
PASSPHRASE = 'secret'

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key_pem)

    print("RSA key pair generated successfully.")
    print("Public Key (OpenSSH format):\n", public_key)
    print("Private Key saved to private_key.pem")

def create_root_ca():
    subprocess.run(['openssl', 'genrsa', '-out', f'{CA_NAME}.key', '4096'])
    subprocess.run(['openssl', 'req', '-x509', '-new', '-nodes', '-key', f'{CA_NAME}.key',
                    '-config', f'{CA_NAME}.req.conf', '-sha256', '-days', '1024', '-out', f'{CA_NAME}.crt'])

    subprocess.run(['openssl', 'pkcs12', '-export', '-out', f'{CA_NAME}.p12', '-inkey', f'{CA_NAME}.key',
                    '-in', f'{CA_NAME}.crt', '-passout', f'pass:{PASSPHRASE}', '-name', f'{CA_NAME}'])

def issue_server_certificate(cert_name):
    subprocess.run(['openssl', 'genrsa', '-out', f'{cert_name}.key', '2048'])
    subprocess.run(['openssl', 'req', '-new', '-key', f'{cert_name}.key', '-config', f'{cert_name}.conf',
                    '-out', f'{cert_name}.csr'])
    subprocess.run(['openssl', 'x509', '-req', '-in', f'{cert_name}.csr', '-CA', f'{CA_NAME}.crt',
                    '-CAkey', f'{CA_NAME}.key', '-CAcreateserial', '-out', f'{cert_name}.crt',
                    '-days', '825', '-sha256', '-passin', f'pass:{PASSPHRASE}', '-extfile', f'{cert_name}.ext'])
    subprocess.run(['openssl', 'pkcs12', '-export', '-out', f'{cert_name}.p12', '-inkey', f'{cert_name}.key',
                    '-in', f'{cert_name}.crt', '-passout', f'pass:', '-name', f'{cert_name}'])
    os.remove(f'{cert_name}.csr')

def issue_client_certificate(cert_name):
    subprocess.run(['openssl', 'genrsa', '-out', f'{cert_name}.key', '2048'])
    subprocess.run(['openssl', 'req', '-new', '-key', f'{cert_name}.key', '-config', f'{cert_name}.conf',
                    '-out', f'{cert_name}.csr'])
    subprocess.run(['openssl', 'x509', '-req', '-in', f'{cert_name}.csr', '-CA', f'{CA_NAME}.crt',
                    '-CAkey', f'{CA_NAME}.key', '-CAcreateserial', '-out', f'{cert_name}.crt',
                    '-days', '825', '-sha256', '-passin', f'pass:{PASSPHRASE}', '-extfile', f'{cert_name}.ext'])
    os.remove(f'{cert_name}.csr')

def main():
    # Start the timer
    start_time = time.time()

    # Generate RSA key pair
    generate_rsa_key_pair()

    # Create root CA
    create_root_ca()

    # Issue server certificate
    issue_server_certificate('localhost')

    # Issue client certificate
    issue_client_certificate('client')

    # Stop the timer
    end_time = time.time()

    # Calculate the total execution time
    execution_time = end_time - start_time

    # Calculate throughput for CA key pair creation
    time_ca_key_pair = time.time() - start_time
    throughput_ca_key_pair = 1 / time_ca_key_pair

    print(f"Time taken for CA key pair generation: {time_ca_key_pair} seconds")
    print(f"Throughput for CA key pair generation: {throughput_ca_key_pair} ops/s")

    # ... (similar calculations for other operations)

    print(f"Total execution time: {execution_time} seconds")

if __name__ == "__main__":
    main()
