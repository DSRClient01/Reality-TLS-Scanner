import json
from typing import Dict, Any
from pathlib import Path
import sys
import locale
import io
from datetime import datetime

def create_html_header():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Reality TLS Scanner Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #1a1a1a;  
                color: #ffffff;  
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                background-color: #2c3e50;
                color: white;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.5);
            }
            .entry {
                background-color: #2d2d2d;  
                padding: 15px;
                margin-bottom: 15px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.3);
                border: 1px solid #3d3d3d;  
            }
            .entry:hover {
                box-shadow: 0 5px 15px rgba(0,0,0,0.4);
                background-color: #333333;  
                transition: all 0.3s ease;
            }
            .label {
                font-weight: bold;
                color: #8e9eab;  
                width: 120px;
                display: inline-block;
            }
            .value {
                color: #ecf0f1; 
            }
            .divider {
                border-bottom: 1px solid #3d3d3d;
                margin: 10px 0;
            }
            .timestamp {
                color: #95a5a6;
                font-size: 0.9em;
                text-align: right;
            }
            .highlight {
                background-color: #2ecc71;  
                color: #000000;  
                padding: 3px 6px;
                border-radius: 3px;
                display: inline-block;
                margin: 2px 0;
            }
            h1 {
                color: #3498db;  
                margin: 0;
                padding-bottom: 10px;
            }
            
            a {
                color: #3498db;
                text-decoration: none;
            }
            a:hover {
                color: #2ecc71;
                text-decoration: underline;
            }
            .table-container {
                margin-top: 20px;
                overflow-x: auto;
            }
            
            .results-table {
                width: 100%;
                border-collapse: collapse;
                background-color: #2d2d2d;
                border-radius: 5px;
                overflow: hidden;
            }
            
            .results-table th {
                background-color: #2c3e50;
                color: #ffffff;
                padding: 12px;
                text-align: left;
                font-weight: bold;
                border-bottom: 2px solid #3498db;
            }
            
            .results-table td {
                padding: 10px;
                border-bottom: 1px solid #3d3d3d;
                color: #ecf0f1;
            }
            
            .results-table tr:hover {
                background-color: #333333;
            }
            
            .results-table .highlight {
                background-color: #2ecc71;
                color: #000000;
                padding: 3px 6px;
                border-radius: 3px;
            }
            
            .subtitle {
                color: #3498db;
                font-size: 1.2em;
                margin: 10px 0;
            }
            
            
            @media screen and (max-width: 768px) {
                .results-table {
                    font-size: 14px;
                }
                
                .results-table th,
                .results-table td {
                    padding: 8px;
                }
            }
            
            .no-results {
                background-color: #2d2d2d;
                padding: 20px;
                border-radius: 5px;
                text-align: center;
                margin-top: 20px;
                border: 1px solid #3d3d3d;
                box-shadow: 0 2px 5px rgba(0,0,0,0.3);
            }
            
            .no-results p {
                font-size: 1.2em;
                color: #e74c3c;
                margin: 0;
            }
        </style>
    </head>
    <body>
    <div class="container">
    """

def create_html_footer():
    return """
    </div>
    </body>
    </html>
    """

def process_scan_results(filename: str) -> None:
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        html_content = [create_html_header()]
        
        
        network = Path(filename).stem.replace('scan_results_final_', '')
        
        
        valid_entries = []
        for entry in data:
            if (entry['ssl_cert'] and 
                'subject' in entry['ssl_cert'] and 
                'CN' in entry['ssl_cert']['subject'] and 
                not any(x in entry['ssl_cert']['subject']['CN'].lower() 
                       for x in ['invalid', 'self-signed', 'localhost'])):
                valid_entries.append(entry)
        
        
        html_content.append(f"""
        <div class="header">
            <h1>Reality TLS Scanner Report</h1>
            <p class="subtitle">Найденные домены для маскировки</p>
            <p class="timestamp">Дата сканирования: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
        </div>
        """)
        
        
        if not valid_entries:
            html_content.append(f"""
            <div class="no-results">
                <p>В введенной сети {network} SNI не найдены!</p>
            </div>
            """)
            html_content.append(create_html_footer())
            return "".join(html_content)
        
        
        html_content.append("""
        <div class="table-container">
            <table class="results-table">
                <thead>
                    <tr>
                        <th>IP-адрес</th>
                        <th>Домен</th>
                        <th>SNI(CN)</th>
                        <th>Страна</th>
                        <th>Провайдер</th>
                        <th>Сертификат</th>
                        <th>Действует до</th>
                    </tr>
                </thead>
                <tbody>
        """)
        
        
        for entry in valid_entries:
            ip = entry['ip']
            domain = entry['domain'] or "Не указан"
            sni = entry['ssl_cert']['subject']['CN']
            
            
            country = "Неизвестно"
            isp = "Неизвестно"
            if entry['geo_info']:
                country = f"{entry['geo_info'].get('country', 'Неизвестно')} ({entry['geo_info'].get('countryCode', 'N/A')})"
                isp = entry['geo_info'].get('isp', 'Неизвестно')
            
            
            cert_issuer = "Неизвестно"
            if entry['ssl_cert'] and 'issuer' in entry['ssl_cert']:
                issuer = entry['ssl_cert']['issuer']
                if 'O' in issuer:
                    cert_issuer = issuer['O']
                elif 'CN' in issuer:
                    cert_issuer = issuer['CN']
            
            
            expires = entry['ssl_cert'].get('expires', 'Неизвестно')
            if expires != 'Неизвестно':
                try:
                    year = expires[0:4]
                    month = expires[4:6]
                    day = expires[6:8]
                    expires = f"{day}.{month}.{year}"
                except:
                    pass

            html_content.append(f"""
            <tr>
                <td>{ip}</td>
                <td>{domain}</td>
                <td class="highlight">{sni}</td>
                <td>{country}</td>
                <td>{isp}</td>
                <td>{cert_issuer}</td>
                <td>{expires}</td>
            </tr>
            """)

        html_content.append("""
                </tbody>
            </table>
        </div>
        """)
        
        html_content.append(create_html_footer())
        return "".join(html_content)

    except FileNotFoundError:
        return f"<p>Файл {filename} не найден</p>"
    except json.JSONDecodeError:
        return f"<p>Ошибка при чтении JSON файла {filename}</p>"
    except Exception as e:
        return f"<p>Произошла ошибка: {str(e)}</p>"

if __name__ == "__main__":
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    
    scan_files = list(Path('.').glob('scan_results_final_*.json'))
    if scan_files:
        latest_file = max(scan_files, key=lambda x: x.stat().st_mtime)
        print(f"Обработка файла: {latest_file}\n")
        html_content = process_scan_results(str(latest_file))
        print(html_content)
    else:
        print("Файлы результатов сканирования не найдены") 