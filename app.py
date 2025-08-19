from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import subprocess
import socket
import threading
import time
import json
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import os
from email_utils import send_email

# Scapy import'unu try-except ile korumalı hale getir
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    print("Scapy yüklü değil. MAC vendor lookup çalışmayabilir.")
    SCAPY_AVAILABLE = False

# MAC vendor lookup'ı korumalı hale getir
try:
    from mac_vendor_lookup import MacLookup
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    print("mac-vendor-lookup yüklü değil. Vendor bilgisi görüntülenemeyecek.")
    MAC_LOOKUP_AVAILABLE = False

app = Flask(__name__)
CORS(app)


EMAIL_SENDER = os.getenv("EMAIL_SENDER", "add your email here")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "add your email here")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "add your email key here")  

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
        self.scanning = False
        self.scan_thread = None
        self._lock = threading.Lock()  # Thread safety için lock
        self.scan_history = self.load_scan_history()  # Mevcut geçmişi yükle

    def load_scan_history(self):
        """Mevcut tarama geçmişini dosyadan yükle"""
        try:
            with open('scan_history.json', 'r', encoding='utf-8') as f:
                history = json.load(f)
                print(f"Tarama geçmişi yüklendi: {len(history)} kayıt")
                return history
        except FileNotFoundError:
            print("scan_history.json dosyası bulunamadı, yeni geçmiş oluşturuluyor")
            return []
        except Exception as e:
            print(f"Tarama geçmişi yüklenirken hata: {e}")
            return []

    def reset_scan(self):
        """Tarama bayrağını ve thread'i sıfırla"""
        with self._lock:
            self.scanning = False
            self.scan_thread = None
            self.active_hosts = []

    def get_local_ip(self):
        """Local IP adresini al"""
        try:
            # Local IP adresini almak için socket kullan
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"Local IP alınamadı: {e}")
            return "127.0.0.1"
    
    def get_network_range(self, ip_or_range):
        """IP adresinden veya aralıktan network rangenı hesapla"""
        try:
            # CIDR veya aralık desteği
            if '/' in ip_or_range:
                # CIDR notasyonu
                net = ipaddress.ip_network(ip_or_range, strict=False)
                return [str(ip) for ip in net.hosts()]
            elif '-' in ip_or_range:
                # Aralık: 192.168.1.10-192.168.1.50
                start_ip, end_ip = ip_or_range.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end)+1)]
            else:
                # Eski davranış: ilk 3 oktet
                ip_parts = ip_or_range.split('.')
                if len(ip_parts) >= 3:
                    network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                    return [f"{network_base}.{i}" for i in range(1, 255)]
                else:
                    raise ValueError("Geçersiz IP formatı")
        except Exception as e:
            print(f"Network Range hatası: {e}")
            return []
    
    def ping_host(self, ip):
        """Tek bir host'a ping at"""
        try:
            if platform.system().lower() == "windows":
                # Windows için ping komutu
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "1000", ip],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    creationflags=subprocess.CREATE_NO_WINDOW  # Windows'ta pencere açmasını engelle
                )
            else:
                # Linux/Mac için ping komutu
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
            
            return ip if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            print(f"Ping timeout: {ip}")
            return None
        except Exception as e:
            print(f"Ping error {ip}: {e}")
            return None
    
    def scan_port(self, ip, port):
        """Belirli bir portu tara"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except Exception as e:
            print(f"Port scan error {ip}:{port} - {e}")
            return None
    
    def get_mac_from_arp(self, ip):
        """Verilen IP için önce scapy ile ARP sorgusu, başarısızsa ARP tablosundan MAC adresini döndür"""
        # Önce scapy ile ARP sorgusu yap (eğer mevcut ise)
        if SCAPY_AVAILABLE:
            try:
                arp = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = srp(packet, timeout=2, verbose=0)[0]
                if result:
                    return result[0][1].hwsrc.lower()
            except Exception as e:
                print(f'Scapy ARP error for {ip}: {e}')
        
        # Scapy başarısızsa veya mevcut değilse eski yöntemi kullan
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(f"arp -a {ip}", shell=True, 
                                               creationflags=subprocess.CREATE_NO_WINDOW).decode()
                match = re.search(r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})", output)
                if match:
                    return match.group(1).replace('-', ':').lower()
            else:
                output = subprocess.check_output(["arp", "-n", ip], timeout=2).decode()
                match = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", output)
                if match:
                    return match.group(1).lower()
        except Exception as e:
            print(f'Fallback ARP error for {ip}: {e}')
        return None

    def get_vendor_from_mac(self, mac):
        """Gerçek vendor bilgisini mac-vendor-lookup ile döndür. Hata olursa 'Bilinmeyen'"""
        if not mac or not MAC_LOOKUP_AVAILABLE:
            return "Bilinmeyen"
        try:
            vendor = MacLookup().lookup(mac)
            return vendor
        except Exception as e:
            print(f"MAC vendor lookup error for {mac}: {e}")
            return "Bilinmeyen"

    def get_hostname(self, ip):
        """IP adresinden hostname al"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception as e:
            print(f"Hostname lookup error for {ip}: {e}")
            return "Bilinmeyen"

    def scan_network(self, scan_ports=False, custom_range=None):
        """Ağdaki aktif host'ları tara ve bağlantısı kopan cihazları bildir"""
        with self._lock:
            self.scanning = True
            self.active_hosts = []
        
        try:
            if custom_range:
                network_range = self.get_network_range(custom_range)
                local_ip = custom_range
            else:
                local_ip = self.get_local_ip()
                network_range = self.get_network_range(local_ip)
            
            print(f"Taranan ağ: {local_ip}")
            print(f"Taranan IP sayısı: {len(network_range)}")
            
            # ThreadPoolExecutor ile paralel ping
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in network_range}
                for future in as_completed(future_to_ip):
                    if not self.scanning:  # Tarama durdurulduysa
                        break
                    try:
                        result = future.result()
                        if result:
                            mac = self.get_mac_from_arp(result)
                            vendor = self.get_vendor_from_mac(mac)
                            host_info = {
                                "ip": result,
                                "hostname": self.get_hostname(result),
                                "mac": mac or "-",
                                "manufacturer": vendor or "-",
                                "ports": []
                            }
                            
                            # Port taraması isteniyorsa
                            if scan_ports:
                                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]
                                with ThreadPoolExecutor(max_workers=20) as port_executor:
                                    port_futures = {port_executor.submit(self.scan_port, result, port): port for port in common_ports}
                                    for port_future in as_completed(port_futures):
                                        port = port_futures[port_future]
                                        try:
                                            port_result = port_future.result()
                                            if port_result:
                                                host_info["ports"].append(port_result)
                                        except Exception as e:
                                            print(f"Port scan error: {e}")
                            
                            with self._lock:
                                self.active_hosts.append(host_info)
                            print(f"Aktif host bulundu: {result} | MAC: {mac} | Vendor: {vendor}")
                    except Exception as e:
                        print(f"Hata: {future_to_ip.get(future, 'Unknown IP')} - {e}")
            
        except Exception as e:
            print(f"Network scan error: {e}")
        finally:
            with self._lock:
                self.scanning = False
        
        # --- Tarama Sonuçlarını Tarihli Olarak Kaydet ---
        from datetime import datetime
        scan_ips = [host['ip'] for host in self.active_hosts if 'ip' in host]
        scan_record = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ips': scan_ips
        }
        # Önceki tarama ile karşılaştır, değişiklik varsa mail gönder
        previous_ips = set()
        if self.scan_history:
            previous_ips = set(self.scan_history[-1]['ips'])
        current_ips = set(scan_ips)
        new_devices = current_ips - previous_ips
        lost_devices = previous_ips - current_ips
        if new_devices or lost_devices:
            try:
                from email_utils import send_email
                import os
                EMAIL_SENDER = os.getenv("EMAIL_SENDER", "add your email here")
                EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "add your email here")
                EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "add your email key here")
                subject = "Network Scan Alert: Change Detected"
                body_lines = []
                if new_devices:
                    body_lines.append(f"New devices found: {', '.join(new_devices)}")
                if lost_devices:
                    body_lines.append(f"Lost devices found: {', '.join(lost_devices)}")
                body_lines.append(f"Date: {scan_record['timestamp']}")
                body = '\n'.join(body_lines)
                send_email(subject, body, EMAIL_SENDER, EMAIL_RECEIVER, EMAIL_PASSWORD)
            except Exception as e:
                print(f"Mail gönderilemedi: {e}")
        with self._lock:
            self.scan_history.append(scan_record)
            # Son 50 kayıt tut (daha fazla geçmiş için)
            if len(self.scan_history) > 50:
                self.scan_history = self.scan_history[-50:]
            # Sonuçları JSON dosyasına kaydet
            try:
                with open('scan_history.json', 'w', encoding='utf-8') as f:
                    json.dump(self.scan_history, f, ensure_ascii=False, indent=2)
                print(f"Tarama geçmişi kaydedildi: {len(self.scan_history)} kayıt")
            except Exception as e:
                print(f"scan_history.json dosyasına yazılamadı: {e}")
        return self.active_hosts
    
    def stop_scan(self):
        """Taramayı durdur"""
        with self._lock:
            self.scanning = False

# Global scanner instance
scanner = NetworkScanner()

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Ağ taramasını başlat"""
    try:
        data = request.get_json() or {}
        scan_ports = data.get('scan_ports', False)
        custom_range = data.get('ip_range') if data.get('ip_range') else None

        # scanning True ise, thread gerçekten çalışıyor mu kontrol et
        if scanner.scanning:
            if scanner.scan_thread and scanner.scan_thread.is_alive():
                return jsonify({"error": "Tarama zaten devam ediyor"}), 400
            else:
                scanner.reset_scan()

        def scan_thread_func():
            try:
                scanner.scan_network(scan_ports, custom_range)
            except Exception as e:
                print(f"Scan thread error: {e}")
            finally:
                with scanner._lock:
                    scanner.scanning = False

        scanner.scan_thread = threading.Thread(target=scan_thread_func)
        scanner.scan_thread.daemon = True
        scanner.scan_thread.start()

        return jsonify({"message": "Tarama başlatıldı", "scanning": True})
    except Exception as e:
        with scanner._lock:
            scanner.scanning = False
        return jsonify({"error": str(e)}), 500

@app.route('/api/status')
def get_status():
    """Tarama durumunu ve sonuçları döndür"""
    with scanner._lock:
        risky_ports = {21, 22, 23, 80, 445, 3389, 8080}
        risky_devices = 0
        for host in scanner.active_hosts:
            if 'ports' in host and host['ports']:
                # portlar int mi string mi? string ise int'e çevir
                port_list = [int(p) for p in host['ports'] if str(p).isdigit()]
                if any(port in risky_ports for port in port_list):
                    risky_devices += 1
        return jsonify({
            "scanning": scanner.scanning,
            "hosts": scanner.active_hosts.copy(),  # Copy to avoid race conditions
            "host_count": len(scanner.active_hosts),
            "risky_devices": risky_devices
        })

@app.route('/api/stop', methods=['POST'])
def stop_scan():
    """Taramayı durdur"""
    try:
        scanner.stop_scan()
        return jsonify({"message": "Tarama durduruldu"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/local-ip')
def get_local_ip():
    """Local IP adresini döndür"""
    try:
        local_ip = scanner.get_local_ip()
        network_range = scanner.get_network_range(local_ip)
        if network_range:
            return jsonify({
                "local_ip": local_ip,
                "network_range": f"{network_range[0].rsplit('.', 1)[0]}.0/24"
            })
        else:
            return jsonify({
                "local_ip": local_ip,
                "network_range": "Hesaplanamadı"
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-history')
def get_scan_history():
    """Scan geçmişini döndür (son 50 kayıt)"""
    try:
        # Memory'deki güncel geçmişi kullan
        with scanner._lock:
            history = scanner.scan_history.copy()
        return jsonify({"history": history})
    except Exception as e:
        return jsonify({"error": str(e), "history": []}), 500

if __name__ == '__main__':
    print("Ağ Tarama Sistemi başlatılıyor...")
    print("Web arayüzü: http://localhost:5000")
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\nKapatılıyor... Tarama durduruluyor.")
        scanner.stop_scan()
        print("Çıkılıyor.")