import socket
import ssl
from urllib.parse import urlparse


class CheckSsl():

    @staticmethod
    def check_ssl(domain: str, timeout: int = 10):

        parsed_url = urlparse(domain)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        domain = domain.rstrip("/")

        try:
            contexto = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with contexto.wrap_socket(sock, server_hostname=domain) as ssock:
                    certificado = ssock.getpeercert()

                    if certificado:
                        return True
                    else:
                        return False

        except ssl.SSLError:
            print(f"Erro SSL ao tentar conectar ao domínio {domain}")
            return False
        except socket.timeout:
            print(f"Tempo de conexão excedido ao tentar conectar ao domínio {domain}.")
            return False
        except socket.error:
            print(f"Erro ao tentar conectar ao domínio {domain} na porta 443.")
            return False
