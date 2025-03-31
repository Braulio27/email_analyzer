import re
import dns.resolver
import dns.exception

def check_dmarc_record(domain):
    """
    Verifica si existe un registro DMARC para el dominio dado.
    Retorna 'pass' si se encuentra un registro con 'v=DMARC1',
    de lo contrario retorna 'none'.
    """
    if not domain:
        return 'none'
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for record in txt_records:
            record_data = "".join(r.decode('utf-8') for r in record.strings)
            if 'v=DMARC1' in record_data.upper():
                return 'pass'
        return 'none'
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return 'none'

def check_rbl(ip, rbl="zen.spamhaus.org"):
    """
    Verifica si la IP aparece en la lista negra del RBL dado (por defecto Spamhaus).
    Retorna True si está en lista negra, False de lo contrario.
    """
    if not ip:
        return False
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False
    reversed_ip = ".".join(ip.split(".")[::-1])
    query = f"{reversed_ip}.{rbl}"
    try:
        dns.resolver.resolve(query, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return False
