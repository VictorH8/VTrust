import socket
import ssl
from urllib.parse import urlparse

from colorama import Fore, Style, init

init(autoreset=True)

class CheckSsl:
    @staticmethod
    def check_ssl(domain: str, timeout: int = 10) -> bool:
        """Verifica se um domínio possui um certificado SSL válido."""

        parsed_url = urlparse(domain)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        domain = domain.rstrip("/")

        try:
            contexto = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with contexto.wrap_socket(sock, server_hostname=domain) as ssock:
                    certificado = ssock.getpeercert()

                    if certificado:
                        validade = certificado.get("notAfter")
                        emissor = certificado.get("issuer")

                        print(f"{Fore.GREEN}[✔] Certificado SSL válido para {domain}.{Style.RESET_ALL}")
                        print(f"    {Fore.CYAN}Emissor: {emissor}{Style.RESET_ALL}")
                        print(f"    {Fore.YELLOW}Válido até: {validade}{Style.RESET_ALL}")

                        return True
                    else:
                        return False

        except ssl.SSLError as e:
            print(f"{Fore.RED}[✘] Erro SSL ao conectar com {domain}: {e}{Style.RESET_ALL}")
            return False
        except socket.timeout:
            print(f"{Fore.RED}[✘] Tempo de conexão excedido ao tentar conectar com {domain}.{Style.RESET_ALL}")
            return False
        except socket.error:
            print(f"{Fore.RED}[✘] Falha ao conectar com {domain} na porta 443.{Style.RESET_ALL}")
            return False
