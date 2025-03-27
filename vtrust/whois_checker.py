from datetime import datetime
import whois
from colorama import Fore, Style, init

init(autoreset=True)

class WhoisChecker:
    def __init__(self):
        self.whois_data = None

    def load_whois_data(self, domain):
        print(f"{Fore.CYAN}[INFO] Buscando dados WHOIS para {domain}...{Style.RESET_ALL}")
        self.whois_data = whois.whois(domain)

    def check_domain_age(self, domain: str, min_days: int = 365) -> bool:
        """
        Verifica se o domínio é mais antigo que a idade mínima especificada (padrão: 365 dias).
            :param domain: O nome do domínio a ser verificado.
            :param min_days: A idade mínima em dias que o domínio deve ter (padrão é 365 dias).
            :return: True se o domínio for mais velho que a idade especificada, False caso contrário.
        """
        if self.whois_data is None:
            self.load_whois_data(domain)

        if not self.whois_data or not hasattr(self.whois_data, 'creation_date'):
            return f"{Fore.RED}[ERRO] Não foi possível obter os dados de criação do domínio {domain}.{Style.RESET_ALL}"
        
        register_date = self.whois_data.creation_date

        if isinstance(register_date, list):
            register_date = register_date[0] if register_date else None

        if register_date is None:
            return f"{Fore.RED}[ERRO] Data de criação do domínio não encontrada para {domain}.{Style.RESET_ALL}"

        if isinstance(register_date, str):
            try:
                register_date = datetime.strptime(register_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return f"{Fore.RED}[ERRO] Formato de data de criação inválido para {domain}.{Style.RESET_ALL}"

        age_days = (datetime.now() - register_date).days

        if age_days >= min_days:
            return f"{Fore.GREEN}[SUCESSO] O domínio {domain} tem mais de {min_days} dias. ({age_days} dias de idade){Style.RESET_ALL}"
        else:
            return f"{Fore.YELLOW}[AVISO] O domínio {domain} tem menos de {min_days} dias. ({age_days} dias de idade){Style.RESET_ALL}"

    def is_domain_active(self, domain: str):
        """
        Verifica se o domínio está ativo com base na sua data de expiração.
            :param domain: O nome do domínio a ser verificado.
            :return: True se o domínio estiver ativo, False se expirado ou sem data de expiração.
        """
        if self.whois_data is None:
            self.load_whois_data(domain)

        if self.whois_data.expiration_date:
            expiration_date = self.whois_data.expiration_date[0]
            expiration_date = expiration_date.date()

            if expiration_date > datetime.now().date():
                return f"{Fore.GREEN}[SUCESSO] O domínio {domain} está ativo. Data de expiração: {expiration_date}{Style.RESET_ALL}"
            else:
                return f"{Fore.RED}[ERRO] O domínio {domain} expirou. Data de expiração: {expiration_date}{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}[ERRO] Não foi encontrada data de expiração para {domain}.{Style.RESET_ALL}"
