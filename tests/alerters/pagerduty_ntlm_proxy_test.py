import base64
import datetime
import socket
import ssl
import struct
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from elastalert.alerters.pagerduty import PagerDutyAlerter
from elastalert.loaders import FileRulesLoader


NTLM_CHALLENGE = (
    'TlRMTVNTUAACAAAAAwAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAABgBwFwAAAA9TAGUAcgB2AGUAcg'
    'ACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA='
)


def read_http_request(connection):
    request = bytearray()
    while b'\r\n\r\n' not in request:
        chunk = connection.recv(4096)
        if not chunk:
            break
        request.extend(chunk)

    headers, separator, body = request.partition(b'\r\n\r\n')
    content_length = 0
    for header in headers.split(b'\r\n')[1:]:
        if header.lower().startswith(b'content-length:'):
            content_length = int(header.split(b':', 1)[1].strip())
            break

    while separator and len(body) < content_length:
        chunk = connection.recv(4096)
        if not chunk:
            break
        body += chunk
    return headers + separator + body


def ntlm_message_type(request):
    for header in request.split(b'\r\n'):
        if header.lower().startswith(b'proxy-authorization: ntlm '):
            token = header.split(None, 2)[2]
            message = base64.b64decode(token)
            assert message[:8] == b'NTLMSSP\x00'
            return struct.unpack('<I', message[8:12])[0]
    raise AssertionError('CONNECT request did not contain an NTLM Proxy-Authorization header')


def create_server_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'events.pagerduty.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('events.pagerduty.com')]), critical=False)
        .sign(key, hashes.SHA256())
    )

    certificate_path = tmp_path / 'proxy-test-certificate.pem'
    key_path = tmp_path / 'proxy-test-key.pem'
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return certificate_path, key_path


def test_pagerduty_alerter_completes_ntlm_connect_handshake(tmp_path):
    certificate_path, key_path = create_server_certificate(tmp_path)
    server = socket.create_server(('127.0.0.1', 0))
    server.settimeout(5)
    proxy_port = server.getsockname()[1]
    observed_message_types = []
    observed_https_requests = []
    server_errors = []

    def serve_proxy_request():
        try:
            connection, _ = server.accept()
            connection.settimeout(5)
            with connection:
                negotiate_request = read_http_request(connection)
                observed_message_types.append(ntlm_message_type(negotiate_request))
                challenge_response = (
                    'HTTP/1.1 407 Proxy Authentication Required\r\n'
                    f'Proxy-Authenticate: NTLM {NTLM_CHALLENGE}\r\n'
                    'Content-Length: 0\r\n'
                    'Proxy-Connection: Keep-Alive\r\n'
                    '\r\n'
                )
                connection.sendall(challenge_response.encode('ascii'))

                authenticate_request = read_http_request(connection)
                observed_message_types.append(ntlm_message_type(authenticate_request))
                connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

                tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls_context.load_cert_chain(certificate_path, key_path)
                with tls_context.wrap_socket(connection, server_side=True) as tls_connection:
                    observed_https_requests.append(read_http_request(tls_connection))
                    tls_connection.sendall(
                        b'HTTP/1.1 202 Accepted\r\n'
                        b'Content-Type: application/json\r\n'
                        b'Content-Length: 2\r\n'
                        b'Connection: close\r\n'
                        b'\r\n'
                        b'{}'
                    )
        except Exception as error:
            server_errors.append(error)

    proxy_thread = threading.Thread(target=serve_proxy_request, daemon=True)
    proxy_thread.start()

    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_proxy': f'http://127.0.0.1:{proxy_port}',
        'pagerduty_proxy_login': r'DOMAIN\user',
        'pagerduty_proxy_pass': 'password',
        'pagerduty_ignore_ssl_errors': True,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }

    try:
        alert.alert([match])
    finally:
        proxy_thread.join(timeout=5)
        server.close()

    assert not proxy_thread.is_alive()
    assert not server_errors
    assert observed_message_types == [1, 3]
    assert len(observed_https_requests) == 1
    assert observed_https_requests[0].startswith(
        b'POST /generic/2010-04-15/create_event.json HTTP/1.1\r\n'
    )
    assert b'"service_key": "magicalbadgers"' in observed_https_requests[0]
