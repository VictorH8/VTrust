from typing import Dict, Optional
from urllib.parse import urlparse

import httpx


class SecurityHeadersChecker:
    def __init__(self, timeout: int = 10):
        """Inicializa o verificador de cabeçalhos de segurança."""
        self.headers_data: Optional[Dict[str, str]] = None
        self.timeout = timeout

    def load_headers(self, domain: str):
        """Carrega os cabeçalhos HTTP de um domínio."""
        try:
            if not domain:
                raise ValueError("O domínio não pode ser vazio.")

            if not domain.startswith(("http://", "https://")):
                domain = f"https://{domain}"

            parsed_url = urlparse(domain)

            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Domínio inválido.")

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
            }

            response = httpx.get(domain, headers=headers, follow_redirects=True, timeout=self.timeout)
            response.raise_for_status()
            self.headers_data = response.headers
            print(f"[INFO] Cabeçalhos carregados com sucesso para: {domain}")

        except httpx.RequestError as e:
            print(f"[ERRO] Erro ao acessar o domínio {domain}: {e}")
            raise ValueError(f"Erro ao acessar o domínio: {e}")

        except httpx.HTTPStatusError as e:
            print(f"[ERRO] Erro na resposta do servidor para {domain}: {e}")
            raise ValueError(f"Erro na resposta do servidor: {e}")

    def is_cache_control_secure(self, domain: str) -> bool:
        """Verifica se o cabeçalho Cache-Control é seguro."""
        if self.headers_data is None:
            self.load_headers(domain)

        headers = self.headers_data

        cache_control = headers.get("cache-control", "").lower()

        if not cache_control:
            print(f"[AVISO] Cache-Control não encontrado para: {domain}")
            return False

        if "max-age=" not in cache_control:
            print(f"[AVISO] max-age não encontrado no Cache-Control para: {domain}")
            return False

        try:
            max_age = int(cache_control.split("max-age=")[1].split(",", 1)[0])
            return max_age >= 31536000

        except (ValueError, IndexError):
            print(f"[AVISO] Erro ao processar max-age no Cache-Control para: {domain}")
            return False

    def check_security_headers(self, domain: str, verbose: bool = True) -> str:
        """Verifica a presença de cabeçalhos de segurança e retorna um status simples."""
        if self.headers_data is None:
            self.load_headers(domain)

        headers = self.headers_data

        security_checks = {
            "cache_control_secure": self.is_cache_control_secure(domain),
            "strict_transport_security": "strict-transport-security" in headers,
            "content_security_policy": "content-security-policy" in headers,
            "x_content_type_options": "x-content-type-options" in headers,
            "x_frame_options": "x-frame-options" in headers,
        }

        secure_threshold = sum(security_checks.values()) >= 3
        status = "SEGURO" if secure_threshold else "INSEGURO"
        message = f"[INFO] O domínio {domain} é {status}."

        if verbose:
            print(message)

        return status
