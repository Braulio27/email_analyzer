# Email Analyzer

Este script analiza un archivo de correo en formato texto para extraer información relevante de los encabezados, realizar verificaciones de autenticación (SPF, DKIM, DMARC) y comprobar si las IPs de los saltos (hops) aparecen en listas negras (RBL). Además, genera un reporte en HTML con gráficos y tablas que resumen los resultados.

## Características

- **Extracción de Encabezados:**  
  - Procesa los encabezados del correo, en particular `Received`, `Authentication-Results`, `DKIM-Signature` y `Received-SPF`.
  - Extrae información clave como la IP, el servidor (by), el protocolo (with) y la fecha/hora de cada salto.

- **Verificación de Autenticación:**  
  - Determina el estado de SPF, DKIM y DMARC usando los encabezados del correo.
  - Realiza una consulta DNS para comprobar la existencia de un registro DMARC en el dominio del remitente si no se encuentra en los resultados de autenticación.

- **Verificación de Listas Negras (RBL):**  
  - Consulta la RBL `zen.spamhaus.org` para verificar si la IP de cada hop está en lista negra.

- **Reporte HTML:**  
  - Genera un archivo `email_analysis.html` que incluye:
    - Sección "Delivery Information" con el estado de autenticación (DMARC, SPF, DKIM) y su alineación.
    - Sección "Relay Information" con una tabla de cada hop (incluyendo delay, IP, servidor, protocolo, hora en UTC y estado de lista negra).
    - Un gráfico de barras (usando Chart.js vía CDN) que visualiza los retrasos (delays) entre hops.

## Requisitos e Instalación

El script requiere **Python 3.6** o superior y las siguientes librerías:

- **Jinja2:** Para la generación del reporte HTML.
- **dnspython:** Para realizar consultas DNS (verificación de DMARC y RBL).

Para instalarlas, utiliza el siguiente comando:

```bash
pip install jinja2 dnspython
```

## Uso

1. **Prepara el archivo de correo:**  
   Asegúrate de tener un archivo de texto (por ejemplo, `email.txt`) con el contenido del correo que deseas analizar.

2. **Ejecuta el script desde la terminal:**  
   Abre una terminal en el directorio donde se encuentre el script y ejecuta:
   ```bash
   python email_analyzer.py email.txt
   ```

- Si el archivo no se encuentra o el número de argumentos es incorrecto, el script mostrará un mensaje de error.
- Una vez procesado el correo, se generará el archivo `email_analysis.html`.

3. **Visualiza el reporte:**  
   Abre `email_analysis.html` en tu navegador para ver el análisis detallado, incluyendo tablas y gráficos.
