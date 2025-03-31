import sys
import os
from email import message_from_file
from report_generator import generate_report
from email_parser import (
    parse_authentication_results, parse_received_headers,
    parse_email_links, parse_attachments
)
from dns_checker import check_dmarc_record
from attachment_hasher import extraer_adjuntos_y_calcular_hash

def main(email_file_path):
    if not os.path.exists(email_file_path):
        print(f"El archivo {email_file_path} no existe.")
        return

    with open(email_file_path, "r", encoding="utf-8", errors="replace") as f:
        msg = message_from_file(f)

    spf_status, dkim_status, dmarc_status, spf_alignment, dkim_alignment = parse_authentication_results(msg)
    hops, total_delay = parse_received_headers(msg)
    links = parse_email_links(msg)
    
    # Extrae información básica de adjuntos (nombre, tipo y tamaño)
    attachments = parse_attachments(msg)
    # Calcula los hashes de los adjuntos usando el módulo attachment_hasher
    hashes_adjuntos = extraer_adjuntos_y_calcular_hash(email_file_path)
    # Asocia el hash a cada adjunto si corresponde
    for att in attachments:
        att["hash"] = hashes_adjuntos.get(att["filename"], "N/A")
    
    report_data = {
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "spf_alignment": spf_alignment,
        "dkim_alignment": dkim_alignment,
        "hops": hops,
        "total_delay": total_delay,
        "links": links,
        "attachments": attachments
    }

    output_path = "reports/output_report.html"
    generate_report(report_data, output_path)
    print(f"Reporte generado en {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py <ruta_del_email>")
    else:
        main(sys.argv[1])
