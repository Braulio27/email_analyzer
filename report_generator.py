from jinja2 import Template

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
            <td>
                {% if hop.ip %}
                    <a href="https://www.virustotal.com/gui/ip-address/{{ hop.ip }}" target="_blank">
                        {{ hop.ip }}
                    </a>
                {% endif %}
            </td>
            <td>{{ hop.by }}</td>
            <td>{{ hop.with_proto }}</td>
            <td>{{ hop.time_utc }}</td>
            <td>{{ hop.blacklisted }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>


    <!-- Sección de Enlaces Encontrados -->
    <h2>Enlaces Encontrados</h2>
    {% if links %}
        <ul>
        {% for link in links %}
            <li><a href="{{ link }}" target="_blank">{{ link }}</a></li>
        {% endfor %}
        </ul>
    {% else %}
        <p>No se encontraron enlaces.</p>
    {% endif %}

    <!-- Sección de Archivos Adjuntos -->
    <h2>Archivos Adjuntos</h2>
    {% if attachments %}
        <table>
            <thead>
                <tr>
                    <th>Nombre del Archivo</th>
                    <th>Tipo de Contenido</th>
                    <th>Tamaño (bytes)</th>
                    <th>Hash</th>
                </tr>
            </thead>
            <tbody>
                {% for att in attachments %}
                <tr>
                    <td>{{ att.filename }}</td>
                    <td>{{ att.content_type }}</td>
                    <td>{{ att.size }}</td>
                    <td>
                    {% if att.hash is defined %}
                        <a href="https://www.virustotal.com/gui/file/{{ att.hash }}/detection" target="_blank">
                    {{ att.hash }}
                        </a>
                    {% else %}
                         N/A
                     {% endif %}
                     </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p>No se encontraron archivos adjuntos.</p>
    {% endif %}

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

def generate_report(report_data, output_file):
    """
    Genera el archivo HTML con los resultados, utilizando el template HTML.
    
    Parámetros:
    - report_data: diccionario que contiene los siguientes campos:
        - spf_status, dkim_status, dmarc_status
        - spf_alignment, dkim_alignment
        - hops (lista de diccionarios con información de cada hop)
        - total_delay (entero con la suma de delays)
        - links (lista de URLs encontradas)
        - attachments (lista de diccionarios con información de archivos adjuntos y su hash)
    - output_file: ruta del archivo de salida HTML.
    """
    # Preparar datos adicionales para el template
    hop_labels = [f"Hop {h['hop_number']}" for h in report_data['hops']]
    hop_delays = [h['delay'] for h in report_data['hops']]

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        spf_status=report_data['spf_status'],
        dkim_status=report_data['dkim_status'],
        dmarc_status=report_data['dmarc_status'],
        spf_alignment=report_data['spf_alignment'],
        dkim_alignment=report_data['dkim_alignment'],
        hops=report_data['hops'],
        total_delay=report_data['total_delay'],
        hop_labels=hop_labels,
        hop_delays=hop_delays,
        links=report_data['links'],
        attachments=report_data['attachments']
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ Análisis completado. Archivo generado: {output_file}")
