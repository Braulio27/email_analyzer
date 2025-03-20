import sys
import re
import os
from email import message_from_file
from email.utils import parsedate_to_datetime
from jinja2 import Template
from datetime import datetime

# Se requiere instalar dnspython
# pip install dnspython
import dns.resolver
import dns.exception

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Análisis de Email</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; padding: 20px; }
        h1, h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
        th { background-color: #f4f4f4; }
        .alert { color: red; font-weight: bold; }
        .info-box { padding: 10px; margin: 10px 0; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .none { color: orange; font-weight: bold; }
        /* Chart container */
        #chart-container {
            width: 80%;
            margin: 0 auto;
            margin-top: 30px;
        }
        canvas {
            max-width: 100%;
        }
    </style>
</head>
<body>
    <h1>Análisis de Email</h1>
    <!-- Sección de Autenticación -->
    <h2>Delivery Information</h2>
    <div class="info-box">
        <p><strong>DMARC:</strong> 
            {% if dmarc_status == 'pass' %}
                <span class="pass">DMARC Compliant</span>
            {% elif dmarc_status == 'fail' %}
                <span class="fail">DMARC Fail</span>
            {% else %}
                <span class="none">No DMARC Record Found</span>
            {% endif %}
        </p>
        <p><strong>SPF Alignment:</strong>
            {% if spf_alignment == 'pass' %}
                <span class="pass">SPF Alineado</span>
            {% elif spf_alignment == 'fail' %}
                <span class="fail">SPF Desalineado</span>
            {% else %}
                <span class="none">No se detectó SPF</span>
            {% endif %}
        </p>
        <p><strong>SPF Authentication:</strong>
            {% if spf_status == 'pass' %}
                <span class="pass">SPF Autenticado</span>
            {% elif spf_status == 'fail' %}
                <span class="fail">SPF Falló</span>
            {% else %}
                <span class="none">Sin datos SPF</span>
            {% endif %}
        </p>
        <p><strong>DKIM Alignment:</strong>
            {% if dkim_alignment == 'pass' %}
                <span class="pass">DKIM Alineado</span>
            {% elif dkim_alignment == 'fail' %}
                <span class="fail">DKIM Desalineado</span>
            {% else %}
                <span class="none">No se detectó DKIM</span>
            {% endif %}
        </p>
        <p><strong>DKIM Authentication:</strong>
            {% if dkim_status == 'pass' %}
                <span class="pass">DKIM Autenticado</span>
            {% elif dkim_status == 'fail' %}
                <span class="fail">DKIM Falló</span>
            {% else %}
                <span class="none">Sin datos DKIM</span>
            {% endif %}
        </p>
    </div>

    <!-- Sección de Relay Information -->
    <h2>Relay Information</h2>
    <p><strong>Received Delay:</strong> {{ total_delay }} seconds</p>
    <table>
        <thead>
            <tr>
                <th>Hop</th>
                <th>Delay (s)</th>
                <th>IP</th>
                <th>By</th>
                <th>With</th>
                <th>Time (UTC)</th>
                <th>Blacklisted</th>
            </tr>
        </thead>
        <tbody>
            {% for hop in hops %}
            <tr>
                <td>{{ hop.hop_number }}</td>
                <td>{{ hop.delay }}</td>
                <td>{{ hop.ip }}</td>
                <td>{{ hop.by }}</td>
                <td>{{ hop.with_proto }}</td>
                <td>{{ hop.time_utc }}</td>
                <td>{{ hop.blacklisted }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <!-- Gráfico de barras -->
    <div id="chart-container">
        <canvas id="myChart"></canvas>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const ctx = document.getElementById('myChart').getContext('2d');
        const hopLabels = {{ hop_labels|safe }};
        const hopDelays = {{ hop_delays|safe }};
        
        const myChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: hopLabels,
                datasets: [{
                    label: 'Delay (segundos)',
                    data: hopDelays,
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    x: { title: { display: true, text: 'Hops' } },
                    y: { title: { display: true, text: 'Segundos' }, beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
"""

def get_domain_from_address(address):
    """
    Extrae el dominio de una dirección de correo.
    Retorna None si no se encuentra.
    """
    domain_match = re.search(r'@([\w.-]+\.[a-zA-Z]{2,})', address)
    if domain_match:
        return domain_match.group(1).lower()
    return None

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
                # Se podría analizar "p=none|quarantine|reject" si se desea más detalle
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
    # Verificar que sea una IP IPv4 válida
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False
    reversed_ip = ".".join(ip.split(".")[::-1])
    query = f"{reversed_ip}.{rbl}"
    try:
        # Si resuelve A, significa que la IP está listada
        dns.resolver.resolve(query, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return False

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

    # Revisar Authentication-Results
    auth_results = msg.get_all('Authentication-Results', [])
    for ar in auth_results:
        # SPF
        match_spf = re.search(r'spf=(pass|fail)', ar, re.IGNORECASE)
        if match_spf:
            spf_status = match_spf.group(1).lower()

        # DKIM
        match_dkim = re.search(r'dkim=(pass|fail)', ar, re.IGNORECASE)
        if match_dkim:
            dkim_status = match_dkim.group(1).lower()

        # DMARC
        match_dmarc = re.search(r'dmarc=(pass|fail)', ar, re.IGNORECASE)
        if match_dmarc:
            dmarc_status = match_dmarc.group(1).lower()

    # Revisar Received-SPF
    received_spf = msg.get('Received-SPF', '')
    if 'pass' in received_spf.lower():
        spf_status = 'pass'
    elif 'fail' in received_spf.lower():
        spf_status = 'fail'

    # DKIM-Signature (para verificar alineación muy básica)
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
        # Si no hay info de Auth-Results para DKIM, ponemos 'fail' por defecto si no se sabe
        if dkim_status == 'none':
            dkim_status = 'fail'

    # SPF Alignment (básico)
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

    # Si DMARC sigue en 'none', hacemos un check DNS
    if dmarc_status == 'none':
        from_addr = msg.get('From', '')
        from_domain = get_domain_from_address(from_addr)
        # Verificamos si el dominio tiene registro DMARC
        dmarc_dns_check = check_dmarc_record(from_domain)
        if dmarc_dns_check == 'pass':
            dmarc_status = 'pass'
        else:
            # "none" implica "No DMARC Record Found"
            dmarc_status = 'none'

    return spf_status, dkim_status, dmarc_status, spf_alignment, dkim_alignment

def parse_received_headers(msg):
    """
    Obtiene información de cada encabezado Received para calcular:
    - Tiempos (fechas) de cada hop.
    - Delays entre hops.
    - Información parcial de "by", "with".
    - Extrae IP para hacer verificación RBL.
    """
    received_headers = msg.get_all("Received", [])
    hops_info = []

    for header in received_headers:
        # Extraer fecha/hora del encabezado
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

        # Extraer "by", "with" e IP
        by_match = re.search(r'\bby\s+([\w.\-]+)', header, re.IGNORECASE)
        with_match = re.search(r'\bwith\s+([\w.\-]+)', header, re.IGNORECASE)

        # IP: buscamos la primera coincidencia [x.x.x.x] o la forma nnn.nnn.nnn.nnn
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

    # Filtramos hops sin fecha y ordenamos por tiempo
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

        # Verificación de listas negras para la IP
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

def generate_html_report(
    spf_status, dkim_status, dmarc_status,
    spf_alignment, dkim_alignment,
    hops, total_delay,
    output_file
):
    """Genera el archivo HTML con los resultados, incluyendo gráfico y tabla de hops."""
    template = Template(HTML_TEMPLATE)

    # Preparamos los datos para el gráfico
    hop_labels = [f"Hop {h['hop_number']}" for h in hops]
    hop_delays = [h['delay'] for h in hops]

    html_content = template.render(
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
        spf_alignment=spf_alignment,
        dkim_alignment=dkim_alignment,
        hops=hops,
        total_delay=total_delay,
        hop_labels=hop_labels,
        hop_delays=hop_delays
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ Análisis completado. Archivo generado: {output_file}")

def main():
    """Función principal que ejecuta el análisis del email."""
    if len(sys.argv) != 2:
        print("Uso: python email_analyzer.py email.txt")
        sys.exit(1)

    email_file = sys.argv[1]

    if not os.path.exists(email_file):
        print(f"❌ Archivo no encontrado: {email_file}")
        sys.exit(1)

    print(f"📩 Analizando archivo: {email_file}...")

    try:
        with open(email_file, "r", encoding="utf-8") as f:
            msg = message_from_file(f)
    except Exception as e:
        print("❌ Error al leer el archivo:", e)
        sys.exit(1)

    # 1. Parsear resultados de autenticación (SPF, DKIM, DMARC)
    spf_status, dkim_status, dmarc_status, spf_alignment, dkim_alignment = parse_authentication_results(msg)

    # 2. Parsear encabezados Received para obtener hops, IPs, delays y verificar listas negras
    hops, total_delay = parse_received_headers(msg)

    # 3. Generar reporte HTML
    output_file = "email_analysis.html"
    generate_html_report(
        spf_status, dkim_status, dmarc_status,
        spf_alignment, dkim_alignment,
        hops, total_delay,
        output_file
    )

if __name__ == "__main__":
    main()
