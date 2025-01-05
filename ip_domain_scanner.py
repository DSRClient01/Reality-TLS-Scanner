import socket
import ssl
import OpenSSL
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any
import dns.resolver
import json
import signal
import sys
from datetime import datetime
import os
import tkinter as tk
from tkinter import messagebox
import threading
import webbrowser

def resource_path(relative_path):
    """Получить абсолютный путь к ресурсу"""
    try:
        
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

class DomainScanner:
    def __init__(self):
        self.geoip_api = "http://ip-api.com/json/"
        self.results = []
        self.is_running = True
        self.scanned_count = 0
        self.total_ips = 0

    def stop_scanning(self):
        """Безопасная остановка сканирования"""
        self.is_running = False
        print("\nОстановка сканирования...")

    def get_ssl_info(self, ip: str, port: int = 443) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    
                    subject = {}
                    for key, value in x509.get_subject().get_components():
                        subject[key.decode('utf-8')] = value.decode('utf-8')
                    
                    issuer = {}
                    for key, value in x509.get_issuer().get_components():
                        issuer[key.decode('utf-8')] = value.decode('utf-8')
                    
                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'expires': x509.get_notAfter().decode('ascii')
                    }
        except Exception as e:
            return None

    def get_geo_info(self, ip: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.geoip_api}{ip}", timeout=5)
            return response.json()
        except:
            return None

    def get_reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def scan_ip(self, ip: str) -> Dict[str, Any]:
        if not self.is_running:
            return None
            
        try:
            result = {
                'ip': ip,
                'domain': self.get_reverse_dns(ip),
                'ssl_cert': self.get_ssl_info(ip),
                'geo_info': self.get_geo_info(ip)
            }
            self.scanned_count += 1
            progress = (self.scanned_count / self.total_ips) * 100
            print(f"Сканирование {ip} завершено [{progress:.1f}%]")
            
            
            if self.scanned_count % 50 == 0:
                self.save_results("scan_results_temp.json")
                
            return result
        except Exception as e:
            print(f"Ошибка при сканировании {ip}: {str(e)}")
            return None

    def scan_network(self, network: str):
        network = ipaddress.ip_network(network)
        self.total_ips = network.num_addresses
        print(f"Всего IP адресов для сканирования: {self.total_ips}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            try:
                for batch in self._batch_ips(network, 50):
                    if not self.is_running:
                        print("Сканирование остановлено пользователем")
                        break
                        
                    results = list(executor.map(self.scan_ip, batch))
                    valid_results = [r for r in results if r is not None]
                    self.results.extend(valid_results)
                    
                    
                    self.save_results("scan_results_temp.json")
                    
            except Exception as e:
                print(f"\nОшибка при сканировании: {str(e)}")
                executor.shutdown(wait=False)
                self.save_results(f"scan_results_interrupted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                raise

    def _batch_ips(self, network, batch_size):
        """Разбивает сеть на пакеты IP-адресов"""
        batch = []
        for ip in network:
            batch.append(str(ip))
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    def save_results(self, filename: str):
        try:
            
            results_to_save = []
            for result in self.results:
                if result is None:
                    continue
                    
                
                clean_result = {
                    'ip': result['ip'],
                    'domain': result['domain'],
                    'ssl_cert': result['ssl_cert'],
                    'geo_info': result['geo_info']
                }
                results_to_save.append(clean_result)
                
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results_to_save, f, indent=4, ensure_ascii=False)
            print(f"Результаты сохранены в файл {filename}")
        except Exception as e:
            print(f"Ошибка при сохранении результатов: {str(e)}")
            
            try:
                backup_file = f"backup_{filename}"
                with open(backup_file, 'w', encoding='utf-8') as f:
                    
                    basic_results = [{
                        'ip': r['ip'],
                        'domain': r['domain'],
                        'geo_info': r['geo_info']
                    } for r in self.results if r is not None]
                    json.dump(basic_results, f, indent=4, ensure_ascii=False)
                print(f"Создана резервная копия результатов в файле {backup_file}")
            except:
                print("Не удалось создать резервную копию результатов")

class ScannerGUI:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            os.makedirs('results', exist_ok=True)
            os.chdir('results')

        self.window = tk.Tk()
        self.window.title("Reality TLS Scanner v1.0")
        self.window.geometry("500x300")
        

        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        

        x = (screen_width - 500) // 2
        y = (screen_height - 300) // 2
        

        self.window.geometry(f"500x300+{x}+{y}")
        

        self.current_scanner = None
        
        self.create_widgets()
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        

        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Обработчик сигнала прерывания"""
        if self.current_scanner:
            self.current_scanner.stop_scanning()
        self.window.quit()

    def create_widgets(self):
   
        main_frame = tk.Frame(self.window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

       
        title_label = tk.Label(main_frame, 
                              text="Reality TLS Scanner", 
                              font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=(0, 20))

        
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=10)

        tk.Label(input_frame, 
                text="Введите сеть для сканирования:",
                font=('Helvetica', 10)).pack(side=tk.LEFT)
        
        self.network_entry = tk.Entry(input_frame, width=30)
        self.network_entry.pack(side=tk.LEFT, padx=10)
        self.network_entry.insert(0, "192.168.1.0/24")

       
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=20)

        
        self.scan_button = tk.Button(button_frame, 
                                   text="Начать сканирование",
                                   command=self.on_scan_click,
                                   width=20,
                                   height=2)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        
        self.stop_button = tk.Button(button_frame,
                                   text="Остановить",
                                   command=self.stop_scan,
                                   width=20,
                                   height=2,
                                   state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        
        status_frame = tk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=10)

        self.status_label = tk.Label(status_frame, 
                                   text="Готов к сканированию",
                                   font=('Helvetica', 10),
                                   wraplength=400)
        self.status_label.pack()

        
        separator = tk.Frame(main_frame, height=2, bg="#3d3d3d")
        separator.pack(fill=tk.X, pady=10)

       
        footer_frame = tk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(5, 0))

        
        dsrclient_label = tk.Label(footer_frame, 
                                  text="Telegram:", 
                                  font=('Helvetica', 10, 'bold'),
                                  fg="#3498db")
        dsrclient_label.pack(side=tk.LEFT)

       
        telegram_link = tk.Label(footer_frame, 
                               text="DSRClient", 
                               font=('Helvetica', 10),
                               fg="#3498db",
                               cursor="hand2")
        telegram_link.pack(side=tk.RIGHT)
        
        
        telegram_link.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/DSRCLIENT"))

       
        def on_enter(e):
            telegram_link.config(fg="#27ae60")

        def on_leave(e):
            telegram_link.config(fg="#2ecc71")

        telegram_link.bind("<Enter>", on_enter)
        telegram_link.bind("<Leave>", on_leave)

    def start_scan(self):
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        network = self.network_entry.get().strip()  
        try:
            
            if '/' not in network:
                raise ValueError("Отсутствует маска подсети (например: /24)")
                
            ip, mask = network.split('/')
            if not 0 <= int(mask) <= 32:
                raise ValueError("Маска подсети должна быть от 0 до 32")
                
            net = ipaddress.ip_network(network, strict=False)
            
            
            if net.num_addresses > 65536:  # Ограничение на /16 сеть
                if not messagebox.askyesno("Предупреждение", 
                    f"Вы собираетесь сканировать большую сеть ({net.num_addresses} адресов).\nЭто может занять длительное время. Продолжить?"):
                    return
            
            self.status_label.config(text="Сканирование начато...")
            self.window.update()
            
            
            self.current_scanner = DomainScanner()
            scanner = self.current_scanner
            
            
            network_base = str(net.network_address)
            current_date = datetime.now().strftime('%Y%m%d')
            
            
            json_output = f"scan_results_final_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            
            scanner.scan_network(network)
            scanner.save_results(json_output)
            
            
            try:
                from process_results import process_scan_results
            except ImportError:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "process_results",
                    resource_path("process_results.py")
                )
                process_results = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(process_results)
                process_scan_results = process_results.process_scan_results
            
            result_file = f"{network_base}.{current_date}.html"
            html_content = process_scan_results(json_output)
            with open(result_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.status_label.config(text=f"Сканирование завершено!\nРезультаты сохранены в:\n{result_file}")
            
            if messagebox.showinfo("Готово", f"Сканирование завершено!\nРезультаты сохранены в:\n{result_file}"):
                
                webbrowser.open(result_file)
            
            
            self.current_scanner = None
            
        except ValueError as ve:
            messagebox.showerror("Ошибка", f"Неверный формат сети: {str(ve)}\nПример: 192.168.1.0/24")
        except Exception as e:
            self.current_scanner = None
            
            import traceback
            print("Произошла ошибка:")
            print(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}\nПроверьте консоль для подробностей")
        finally:
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def on_scan_click(self):
        thread = threading.Thread(target=self.start_scan)
        thread.daemon = True
        thread.start()

    def on_closing(self):
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
            if self.current_scanner:
                self.current_scanner.stop_scanning()
            self.window.quit()
            sys.exit(0)

    def stop_scan(self):
        if self.current_scanner:
            self.current_scanner.stop_scanning()
            self.status_label.config(text="Останавливаем сканирование...")

    def run(self):
        self.window.mainloop()

def main():
    app = ScannerGUI()
    app.run()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        
        import traceback
        print("Критическая ошибка при запуске:")
        print(traceback.format_exc())
        
        
        error_window = tk.Tk()
        error_window.title("Ошибка")
        error_window.geometry("400x200")
        
        tk.Label(error_window, 
                text=f"Произошла ошибка при запуске:\n{str(e)}", 
                wraplength=350).pack(pady=20)
        
        tk.Button(error_window, 
                 text="OK", 
                 command=lambda: (error_window.destroy(), sys.exit(1))).pack()
        
        error_window.mainloop() 