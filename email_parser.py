import re
from email.utils import parsedate_to_datetime
from dns_checker import check_dmarc_record, check_rbl
import hashlib

def get_domain_from_address(address):
    """
    Extrae el dominio de una dirección de correo.
    Retorna None si no se encuentra.
    """
    domain_match = re.search(r'@([\w.-]+\.[a-zA-Z]{2,})', address)
    if domain_match:
        return domain_match.group(1).lower()
    return None

def parse_authentication_results(msg):
    """
    Extrae resultados básicos de autenticación (SPF, DKIM, DMARC)
    a partir de los encabezados del mensaje.
    Luego hace una verificación DNS para DMARC si no aparece en Auth-Results.
    """
    spf_status = 'none'
    dkim_status = 'none'
    dmarc_status = 'none'
    spf_alignment = 'none'
    dkim_alignment = 'none'

    auth_results = msg.get_all('Authentication-Results', [])
    for ar in auth_results:
        match_spf = re.search(r'spf=(pass|fail)', ar, re.IGNORECASE)
        if match_spf:
            spf_status = match_spf.group(1).lower()
        match_dkim = re.search(r'dkim=(pass|fail)', ar, re.IGNORECASE)
        if match_dkim:
            dkim_status = match_dkim.group(1).lower()
        match_dmarc = re.search(r'dmarc=(pass|fail)', ar, re.IGNORECASE)
        if match_dmarc:
            dmarc_status = match_dmarc.group(1).lower()

    received_spf = msg.get('Received-SPF', '')
    if 'pass' in received_spf.lower():
        spf_status = 'pass'
    elif 'fail' in received_spf.lower():
        spf_status = 'fail'

    dkim_signature = msg.get_all('DKIM-Signature', [])
    if dkim_signature:
        from_addr = msg.get('From', '')
        from_domain = get_domain_from_address(from_addr)
        for sig in dkim_signature:
            dkim_domain_match = re.search(r'd=([\w.-]+\.[a-zA-Z]{2,})', sig)
            if dkim_domain_match and from_domain:
                dkim_domain = dkim_domain_match.group(1).lower()
                if from_domain in dkim_domain:
                    dkim_alignment = 'pass'
                    break
                else:
                    dkim_alignment = 'fail'
        if dkim_status == 'none':
            dkim_status = 'fail'

    if spf_status == 'pass':
        from_addr = msg.get('From', '')
        from_domain = get_domain_from_address(from_addr)
        return_path = msg.get('Return-Path', '')
        rp_domain = get_domain_from_address(return_path)
        if from_domain and rp_domain:
            if from_domain in rp_domain:
                spf_alignment = 'pass'
            else:
                spf_alignment = 'fail'

    if dmarc_status == 'none':
        from_addr = msg.get('From', '')
        from_domain = get_domain_from_address(from_addr)
        dmarc_dns_check = check_dmarc_record(from_domain)
        if dmarc_dns_check == 'pass':
            dmarc_status = 'pass'
        else:
            dmarc_status = 'none'

    return spf_status, dkim_status, dmarc_status, spf_alignment, dkim_alignment

def parse_received_headers(msg):
    """
    Obtiene información de cada encabezado Received para calcular:
    - Tiempos (fechas) de cada hop.
    - Delays entre hops.
    - Información parcial de "by" y "with".
    - Extrae IP para hacer verificación RBL.
    """
    received_headers = msg.get_all("Received", [])
    hops_info = []

    for header in received_headers:
        date_match = re.search(
            r'(\d{1,2}\s+\w+\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[+-]\d{4})',
            header
        )
        header_time = None
        if date_match:
            try:
                header_time = parsedate_to_datetime(date_match.group(1))
            except:
                pass

        by_match = re.search(r'\bby\s+([\w.\-]+)', header, re.IGNORECASE)
        with_match = re.search(r'\bwith\s+([\w.\-]+)', header, re.IGNORECASE)
        ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', header)
        ip_addr = ip_match.group(1) if ip_match else ''

        hop_data = {
            'header_text': header,
            'time': header_time,
            'by': by_match.group(1) if by_match else '',
            'with_proto': with_match.group(1) if with_match else '',
            'ip': ip_addr
        }
        hops_info.append(hop_data)

    # Filtra los hops sin tiempo y los ordena cronológicamente
    hops_info = [h for h in hops_info if h['time'] is not None]
    hops_info.sort(key=lambda x: x['time'])

    final_hops = []
    total_delay = 0.0
    for i in range(len(hops_info)):
        if i == 0:
            delay = 0
        else:
            delay = (hops_info[i]['time'] - hops_info[i-1]['time']).total_seconds()
            if delay < 0:
                delay = 0
            total_delay += delay

        is_blacklisted = check_rbl(hops_info[i]['ip'])
        blacklisted_str = "Yes" if is_blacklisted else "No"

        final_hops.append({
            'hop_number': i + 1,
            'delay': int(delay),
            'ip': hops_info[i]['ip'],
            'by': hops_info[i]['by'],
            'with_proto': hops_info[i]['with_proto'],
            'time_utc': hops_info[i]['time'].strftime('%Y-%m-%d %H:%M:%S %z'),
            'blacklisted': blacklisted_str
        })

    return final_hops, int(total_delay)

def parse_email_links(msg):
    """
    Extrae enlaces (URLs) del contenido del correo.
    Recorre las partes 'text/plain' y 'text/html' y utiliza regex para extraerlos.
    """
    links = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                        found_links = re.findall(r'(https?://[^\s]+)', text)
                        links.extend(found_links)
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(msg.get_content_charset() or 'utf-8', errors='replace')
                found_links = re.findall(r'(https?://[^\s]+)', text)
                links.extend(found_links)
        except Exception:
            pass
    return list(set(links))

def parse_attachments(msg):
    """
    Extrae información de archivos adjuntos.
    Busca partes con Content-Disposition 'attachment' y recopila nombre, tipo y tamaño.
    """
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            if content_disposition:
                dispositions = content_disposition.strip().split(";")
                if dispositions[0].lower() == "attachment":
                    filename = part.get_filename() or "Sin nombre"
                    content_type = part.get_content_type()
                    payload = part.get_payload(decode=True)
                    if payload:
                        size = len(payload)
                        file_hash = hashlib.sha256(payload).hexdigest()  # Calcula el hash SHA-256
                    else:
                        size = 0
                        file_hash = None
                    size = len(payload) if payload else 0
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": size,
                         "sha256": file_hash
                    })
    return attachments
