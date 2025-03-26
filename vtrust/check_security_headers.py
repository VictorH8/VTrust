import logging
import os
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx

project_root = os.getcwd()
log_file_path = os.path.join(project_root, 'security_headers.log')

logging.basicConfig(
    filename=log_file_path,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

logger = logging.getLogger(__name__)

class SecurityHeadersChecker:
    def __init__(self, timeout: int = 10):
        """
        Inicializa o verificador de cabeçalhos de segurança.
        :param timeout: Timeout em segundos para requisição HTTP.
        """
        self.headers_data: Optional[Dict[str, str]] = None
        self.timeout = timeout

    def load_headers(self, domain: str):
        """
        Carrega os cabeçalhos HTTP de um domínio.

        :param domain: O domínio a ser verificado.
        :raises ValueError: Se o domínio for inválido ou a requisição falhar.
        """
        try:
            if not domain:
                raise ValueError("O domínio não pode ser vazio.")

            if not domain.startswith(("http://", "https://")):
                domain = f"https://{domain}"

            parsed_url = urlparse(domain)

            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Domínio inválido.")

            response = httpx.get(domain, follow_redirects=True, timeout=self.timeout)
            response.raise_for_status()
            self.headers_data = response.headers
            logger.info(f"Cabeçalhos carregados com sucesso para: {domain}")

        except httpx.RequestError as e:
            logger.error(f"Erro ao acessar o domínio {domain}: {e}")
            raise ValueError(f"Erro ao acessar o domínio: {e}")

        except httpx.HTTPStatusError as e:
            logger.error(f"Erro na resposta do servidor para {domain}: {e}")
            raise ValueError(f"Erro na resposta do servidor: {e}")

    def is_cache_control_secure(self, domain: str) -> bool:
        """
        Verifica se o cabeçalho Cache-Control é seguro.
        :param domain: O domínio a ser verificado.
        :return: True se o Cache-Control estiver seguro, False caso contrário.
        """
        if self.headers_data is None:
            self.load_headers(domain)

        headers = self.headers_data

        if "cache-control" not in headers:
            logger.warning(f"Cache-Control não encontrado para: {domain}")
            return False

        cache_control = headers["cache-control"].lower()

        if "max-age=" not in cache_control:
            logger.warning(f"max-age não encontrado no Cache-Control para: {domain}")
            return False

        try:
            max_age = int(cache_control.split("max-age=")[1].split(",", 1)[0])
            return max_age >= 31536000

        except (ValueError, IndexError):
            logger.warning(f"Erro ao processar max-age no Cache-Control para: {domain}")
            return False

    def check_security_headers(self, domain: str) -> Dict[str, bool]:
        """
        Verifica a presença de cabeçalhos de segurança.

        :param domain: O domínio a ser verificado.
        :return: Um dicionário com os resultados da verificação.
        """
        if self.headers_data is None:
            self.load_headers(domain)

        headers = self.headers_data

        results = {
            "cache_control_secure": self.is_cache_control_secure(domain),
            "strict_transport_security": "strict-transport-security" in headers,
            "content_security_policy": "content-security-policy" in headers,
            "x_content_type_options": "x-content-type-options" in headers,
            "x_frame_options": "x-frame-options" in headers,
        }

        logger.info(f"Resultados de verificação de cabeçalhos para {domain}: {results}")
        return results

