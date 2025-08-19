// static/js/app.js
document.addEventListener("DOMContentLoaded", () => {
    const scanBtn = document.getElementById("scanBtn");
    const stopBtn = document.getElementById("stopBtn");
    const statusDiv = document.getElementById("status");
    const resultBody = document.getElementById("resultBody");
    const portScan = document.getElementById("portScan");
    const ipInfo = document.getElementById("ipInfo");

    let polling = null;

    // Sekmeler
    const tabs = {
        dashboardTab: document.getElementById("dashboardTab"),
        scanResultsTab: document.getElementById("scanResultsTab"),
        settingsTab: document.getElementById("settingsTab"),
        dashboardSection: document.getElementById("dashboardSection"),
        scanResultsSection: document.getElementById("scanResultsSection"),
        settingsSection: document.getElementById("settingsSection"),
    };

    Object.keys(tabs).forEach(key => {
        if (key.endsWith("Tab")) {
            const sectionKey = key.replace("Tab", "Section");
            tabs[key].onclick = () => {
                Object.keys(tabs).forEach(k => {
                    if (k.endsWith("Tab")) tabs[k].classList.remove("active");
                    if (k.endsWith("Section")) tabs[k].style.display = "none";
                });
                // Varsayılan olarak gizle; dashboard'a geçiliyorsa hemen göster
                const dashboardWrapper = document.getElementById("dashboardResultTableWrapper");
                if (dashboardWrapper) dashboardWrapper.style.display = "none";
                tabs[key].classList.add("active");
                tabs[sectionKey].style.display = "block";
                if (sectionKey === "dashboardSection") {
                    if (dashboardWrapper) dashboardWrapper.style.display = "block";
                }
                if (sectionKey === "scanResultsSection") fetchScanHistory();
                if (sectionKey === "settingsSection") loadSettings();
            };
        }
    });

    // Tarama geçmişini yükle
    function fetchScanHistory() {
        fetch("/api/scan-history")
            .then(r => r.json())
            .then(data => {
                const history = data.history || [];
                const tbody = document.getElementById("historyBody");
                const filter = document.getElementById("historyDateFilter").value;
                tbody.innerHTML = "";

                let filtered = filter ? history.filter(h => h.timestamp.startsWith(filter)) : history;
                if (filtered.length === 0) {
                    document.getElementById("noHistoryMsg").style.display = "block";
                    document.getElementById("historyTable").style.display = "none";
                } else {
                    document.getElementById("noHistoryMsg").style.display = "none";
                    document.getElementById("historyTable").style.display = "table";
                    filtered.slice().reverse().forEach(item => {
                        const date = item.timestamp.replace(" ", "<br>");
                        const ipList = item.ips.join(", ");
                        tbody.innerHTML += `
                            <tr>
                                <td>${date}</td>
                                <td>${item.ips.length}</td>
                                <td style="word-break:break-all;">${ipList}</td>
                            </tr>`;
                    });
                }
            });
    }

    document.getElementById("historyDateFilter").addEventListener("change", fetchScanHistory);

    // IP bilgisi
    function fetchIpInfo() {
        ipInfo.innerHTML = "Loading...";
        fetch("/api/local-ip")
            .then(r => r.json())
            .then(data => {
                ipInfo.textContent = `Local IP: ${data.local_ip} | Network: ${data.network_range}`;
            })
            .catch(() => ipInfo.textContent = "Network info not available.");
    }

    // Tarama başlat
    function startScan() {
        scanBtn.disabled = true;
        stopBtn.disabled = false;
        statusDiv.textContent = "Scanning started...";
        // Dashboard sonuç tablosu sarmalayıcısını görünür yap
        const dashboardWrapper = document.getElementById("dashboardResultTableWrapper");
        if (dashboardWrapper) dashboardWrapper.style.display = "block";

        const ip_range = document.getElementById("manualMode").checked
            ? document.getElementById("manualRange").value.trim()
            : null;

        if (document.getElementById("manualMode").checked && !ip_range) {
            statusDiv.textContent = "Please enter a valid IP range!";
            scanBtn.disabled = false;
            stopBtn.disabled = true;
            return;
        }

        fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scan_ports: portScan.checked, ip_range })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                statusDiv.textContent = "Error: " + data.error;
                scanBtn.disabled = false;
                stopBtn.disabled = true;
            } else {
                statusDiv.textContent = "Scanning...";
                polling = setInterval(fetchStatus, 1000);
            }
        })
        .catch(() => {
            statusDiv.textContent = "Server connection error.";
            scanBtn.disabled = false;
            stopBtn.disabled = true;
        });
    }

    // Tarama durdur
    function stopScan() {
        fetch("/api/stop", { method: "POST" })
            .then(() => {
                statusDiv.textContent = "Scanning stopped.";
                scanBtn.disabled = false;
                stopBtn.disabled = true;
                if (polling) clearInterval(polling);
            });
    }

    // Durum güncelle
    function fetchStatus() {
        fetch("/api/status")
            .then(r => r.json())
            .then(data => {
                document.getElementById("totalDevices").textContent = data.host_count || 0;
                document.getElementById("totalPorts").textContent = data.open_ports || 0;
                document.getElementById("riskyDevices").textContent = data.risky_devices || 0;

                if (!data.scanning) {
                    statusDiv.textContent = `Scanning completed. Found: ${data.host_count}`;
                    scanBtn.disabled = false;
                    stopBtn.disabled = true;
                    if (polling) clearInterval(polling);
                } else {
                    statusDiv.textContent = `Scanning... Found: ${data.host_count}`;
                }

                if (data.hosts && data.hosts.length > 0) {
                    console.log("📱 Cihazlar bulundu:", data.hosts);
                    // Sonuç tablosunu ve sarmalayıcıyı göster
                    const dashboardWrapper = document.getElementById("dashboardResultTableWrapper");
                    if (dashboardWrapper) dashboardWrapper.style.display = "block";
                    document.getElementById("resultTable").style.display = "table";
                    resultBody.innerHTML = "";
                    data.hosts.forEach(host => {
                        const statusClass = host.status === "up" ? "status-up" : "status-unknown";
                        const manufacturer = (host.manufacturer || "").toString().toLowerCase();
                        let icon = '<i class="fas fa-desktop"></i>';
                        if (manufacturer.includes("printer")) icon = '<i class="fas fa-print"></i>';
                        if (manufacturer.includes("router")) icon = '<i class="fas fa-wifi"></i>';
                        if (manufacturer.includes("server")) icon = '<i class="fas fa-server"></i>';

                        resultBody.innerHTML += `
                            <tr>
                                <td class="row-icon"><span class="status-dot ${statusClass}"></span>${icon}</td>
                                <td>${host.hostname || "-"}</td>
                                <td>${host.ip}</td>
                                <td>${host.manufacturer || "-"}</td>
                                <td>${host.mac || "-"}</td>
                                <td>${(host.ports || []).join(", ") || "-"}</td>
                            </tr>`;
                    });
                }
            });
    }

    // Event listeners
    scanBtn.addEventListener("click", startScan);
    stopBtn.addEventListener("click", stopScan);
    document.getElementById("autoMode").addEventListener("change", () => {
        document.querySelector(".manual-range-container").style.display = "none";
    });
    document.getElementById("manualMode").addEventListener("change", () => {
        document.querySelector(".manual-range-container").style.display = "flex";
    });

    // Dil desteği
    const translations = {
        tr: {
            "Network Scan System": "Ağ Tarama Sistemi",
            "Dashboard": "Panel",
            "Scan Results": "Sonuçlar",
            "Settings": "Ayarlar",
            "Total Devices": "Toplam Cihaz",
            "Open Ports": "Açık Portlar",
            "Risky Devices": "Riskli Cihazlar",
            "Scan": "Tara",
            "Stop": "Durdur",
            "Manual IP range": "Manuel IP Aralığı",
            "Scan open ports": "Portları tara",
            "Automatic": "Otomatik",
            "Ready": "Hazır",
            "Scanning started...": "Tarama başladı...",
            "Scanning in progress...": "Tarama devam ediyor...",
            "Scanning completed.": "Tarama tamamlandı.",
            "No records found.": "Kayıt bulunamadı.",
            "Filter by date": "Tarihe göre filtrele",
            "Date/Time": "Tarih/Saat",
            "Device Count": "Cihaz Sayısı",
            "IP List": "IP Listesi",
            "Name": "İsim",
            "IP": "IP",
            "Manufacturer": "Üretici",
            "MAC Address": "MAC Adresi",
            "Language / Dil": "Dil",
            "Theme / Tema": "Tema",
            "Select Language:": "Dil Seçin:",
            "Select Theme:": "Tema Seçin:",
            "Scan Settings": "Tarama Ayarları",
            "Ping Timeout (ms):": "Ping Zaman Aşımı (ms):",
            "Max Concurrent Workers:": "Maksimum Eşzamanlı İşçi:",
            "Common Ports to Scan:": "Taranacak Yaygın Portlar:",
            "Notification Settings": "Bildirim Ayarları",
            "Email Notifications:": "E-posta Bildirimleri:",
            "Notification Email:": "Bildirim E-postası:",
            "Auto Scan Interval (minutes):": "Otomatik Tarama Aralığı (dakika):",
            "0 = Disabled": "0 = Devre Dışı",
            "Display Settings": "Görüntüleme Ayarları",
            "Max History Records:": "Maksimum Geçmiş Kaydı:",
            "Show Offline Devices:": "Çevrimdışı Cihazları Göster:",
            "Auto Refresh Interval (seconds):": "Otomatik Yenileme Aralığı (saniye):",
            "Export Settings": "Dışa Aktarma Ayarları",
            "Default Export Format:": "Varsayılan Dışa Aktarma Formatı:",
            "Include Port Information:": "Port Bilgilerini Dahil Et:",
            "Save Settings": "Ayarları Kaydet",
            "Reset to Defaults": "Varsayılana Sıfırla",
            "Export Settings": "Ayarları Dışa Aktar"
        },
        en: {
            "Network Scan System": "Network Scan System",
            "Dashboard": "Dashboard",
            "Scan Results": "Scan Results",
            "Settings": "Settings",
            "Total Devices": "Total Devices",
            "Open Ports": "Open Ports",
            "Risky Devices": "Risky Devices",
            "Scan": "Scan",
            "Stop": "Stop",
            "Manual IP range": "Manual IP Range",
            "Scan open ports": "Scan open ports",
            "Automatic": "Automatic",
            "Ready": "Ready",
            "Scanning started...": "Scanning started...",
            "Scanning in progress...": "Scanning in progress...",
            "Scanning completed.": "Scanning completed.",
            "No records found.": "No records found.",
            "Filter by date": "Filter by date",
            "Date/Time": "Date/Time",
            "Device Count": "Device Count",
            "IP List": "IP List",
            "Name": "Name",
            "IP": "IP",
            "Manufacturer": "Manufacturer",
            "MAC Address": "MAC Address",
            "Language / Dil": "Language",
            "Theme / Tema": "Theme",
            "Select Language:": "Select Language:",
            "Select Theme:": "Select Theme:",
            "Scan Settings": "Scan Settings",
            "Ping Timeout (ms):": "Ping Timeout (ms):",
            "Max Concurrent Workers:": "Max Concurrent Workers:",
            "Common Ports to Scan:": "Common Ports to Scan:",
            "Notification Settings": "Notification Settings",
            "Email Notifications:": "Email Notifications:",
            "Notification Email:": "Notification Email:",
            "Auto Scan Interval (minutes):": "Auto Scan Interval (minutes):",
            "0 = Disabled": "0 = Disabled",
            "Display Settings": "Display Settings",
            "Max History Records:": "Max History Records:",
            "Show Offline Devices:": "Show Offline Devices:",
            "Auto Refresh Interval (seconds):": "Auto Refresh Interval (seconds):",
            "Export Settings": "Export Settings",
            "Default Export Format:": "Default Export Format:",
            "Include Port Information:": "Include Port Information:",
            "Save Settings": "Save Settings",
            "Reset to Defaults": "Reset to Defaults",
            "Export Settings": "Export Settings"
        }
    };

    function applyLanguage(lang) {
        document.querySelectorAll("[data-translate]").forEach(el => {
            const key = el.getAttribute("data-translate");
            if (translations[lang][key]) el.textContent = translations[lang][key];
        });
        document.querySelectorAll("[data-translate-placeholder]").forEach(el => {
            const key = el.getAttribute("data-translate-placeholder");
            if (translations[lang][key]) {
                el.placeholder = translations[lang][key];
                // Date input için özel işlem
                if (el.id === "historyDateFilter") {
                    el.value = ""; // Mevcut değeri temizle
                }
            }
        });
    }

    function loadSettings() {
        const lang = localStorage.getItem("language") || "en";
        const theme = localStorage.getItem("theme") || "dark";
        
        // Temel ayarlar
        document.getElementById("languageSelect").value = lang;
        document.getElementById("themeSelect").value = theme;
        
        // Tarama ayarları
        document.getElementById("pingTimeout").value = localStorage.getItem("pingTimeout") || "1000";
        document.getElementById("maxWorkers").value = localStorage.getItem("maxWorkers") || "50";
        document.getElementById("commonPorts").value = localStorage.getItem("commonPorts") || "21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080";
        
        // Görüntüleme ayarları
        document.getElementById("maxHistoryRecords").value = localStorage.getItem("maxHistoryRecords") || "50";
        document.getElementById("showOfflineDevices").checked = localStorage.getItem("showOfflineDevices") === "true";
        document.getElementById("autoRefreshInterval").value = localStorage.getItem("autoRefreshInterval") || "5";
        
        // Dışa aktarma ayarları
        document.getElementById("exportFormat").value = localStorage.getItem("exportFormat") || "json";
        document.getElementById("includePortsInExport").checked = localStorage.getItem("includePortsInExport") !== "false";
        
        applyLanguage(lang);
        applyTheme(theme);
    }

    function saveSettings() {
        // Tarama ayarları
        localStorage.setItem("pingTimeout", document.getElementById("pingTimeout").value);
        localStorage.setItem("maxWorkers", document.getElementById("maxWorkers").value);
        localStorage.setItem("commonPorts", document.getElementById("commonPorts").value);
        
        // Görüntüleme ayarları
        localStorage.setItem("maxHistoryRecords", document.getElementById("maxHistoryRecords").value);
        localStorage.setItem("showOfflineDevices", document.getElementById("showOfflineDevices").checked);
        localStorage.setItem("autoRefreshInterval", document.getElementById("autoRefreshInterval").value);
        
        // Dışa aktarma ayarları
        localStorage.setItem("exportFormat", document.getElementById("exportFormat").value);
        localStorage.setItem("includePortsInExport", document.getElementById("includePortsInExport").checked);
    }

    function resetSettings() {
        // Tüm ayarları varsayılan değerlere sıfırla
        localStorage.removeItem("pingTimeout");
        localStorage.removeItem("maxWorkers");
        localStorage.removeItem("commonPorts");
        localStorage.removeItem("maxHistoryRecords");
        localStorage.removeItem("showOfflineDevices");
        localStorage.removeItem("autoRefreshInterval");
        localStorage.removeItem("exportFormat");
        localStorage.removeItem("includePortsInExport");
        
        // Sayfayı yeniden yükle
        loadSettings();
    }

    function exportSettings() {
        const settings = {
            pingTimeout: document.getElementById("pingTimeout").value,
            maxWorkers: document.getElementById("maxWorkers").value,
            commonPorts: document.getElementById("commonPorts").value,
            maxHistoryRecords: document.getElementById("maxHistoryRecords").value,
            showOfflineDevices: document.getElementById("showOfflineDevices").checked,
            autoRefreshInterval: document.getElementById("autoRefreshInterval").value,
            exportFormat: document.getElementById("exportFormat").value,
            includePortsInExport: document.getElementById("includePortsInExport").checked,
            language: localStorage.getItem("language") || "en",
            theme: localStorage.getItem("theme") || "dark"
        };

        const dataStr = JSON.stringify(settings, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'network_scanner_settings.json';
        link.click();
        URL.revokeObjectURL(url);
        
        showNotification("Ayarlar dışa aktarıldı!", "success");
    }

    function showNotification(message, type = "info") {
        // Basit bildirim sistemi
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        
        if (type === "success") {
            notification.style.background = "linear-gradient(90deg, #27C46B, #1E9B4F)";
        } else if (type === "error") {
            notification.style.background = "linear-gradient(90deg, #FF6B6B, #E55555)";
        } else {
            notification.style.background = "linear-gradient(90deg, #8A63FF, #6B4DE5)";
        }
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = "slideOut 0.3s ease";
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    function applyTheme(theme) {
        document.body.className = theme === "light" ? "light-theme" : "";
    }

    document.getElementById("languageSelect").addEventListener("change", e => {
        const lang = e.target.value;
        localStorage.setItem("language", lang);
        applyLanguage(lang);
    });

    document.getElementById("themeSelect").addEventListener("change", e => {
        const theme = e.target.value;
        localStorage.setItem("theme", theme);
        applyTheme(theme);
    });

    // Settings butonları
    document.getElementById("saveSettingsBtn").addEventListener("click", () => {
        saveSettings();
        showNotification("Ayarlar kaydedildi!", "success");
    });

    document.getElementById("resetSettingsBtn").addEventListener("click", () => {
        if (confirm("Tüm ayarları varsayılan değerlere sıfırlamak istediğinizden emin misiniz?")) {
            resetSettings();
            showNotification("Ayarlar varsayılan değerlere sıfırlandı!", "info");
        }
    });

    document.getElementById("exportSettingsBtn").addEventListener("click", () => {
        exportSettings();
    });

    // Başlat
    fetchIpInfo();
    loadSettings();
});