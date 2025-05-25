
const questions = [


  {
    "q": "ARP Poisoning saldırısının temel prensibi nedir?",
    "options": [
      "A) DNS kayıtlarını değiştirmek",
      "B) ARP tablosunda sahte kayıtlar oluşturmak",
      "C) Routing tablosunu bozmak",
      "D) DHCP server'ı çökertmek",
      "E) Firewall kurallarını bypass etmek"
    ],
    "answer": 1
  },
  {
    "q": "Man-in-the-Middle saldırısında saldırgan ne yapar?",
    "options": [
      "A) Ağ bağlantısını keser",
      "B) İki taraf arasında gizlice iletişimi dinler/manipüle eder",
      "C) Sadece şifreleri kırır",
      "D) Sistem dosyalarını değiştirir",
      "E) Firewall'ı devre dışı bırakır"
    ],
    "answer": 1
  },
  {
    "q": "ARP protokolü hangi OSI katmanında çalışır?",
    "options": [
      "A) Layer 1 (Physical)",
      "B) Layer 2 (Data Link)",
      "C) Layer 3 (Network)",
      "D) Layer 4 (Transport)",
      "E) Layer 7 (Application)"
    ],
    "answer": 1
  },
  {
    "q": "Ettercap aracının temel işlevi nedir?",
    "options": [
      "A) Port tarama",
      "B) ARP Poisoning ve MITM saldırıları",
      "C) Dosya şifreleme",
      "D) Sistem yedekleme",
      "E) Network monitoring"
    ],
    "answer": 1
  },
  {
    "q": "ARP Poisoning saldırısından korunmanın en etkili yolu nedir?",
    "options": [
      "A) Dynamic ARP Inspection (DAI)",
      "B) Güçlü parolalar",
      "C) Antivirus kullanmak",
      "D) Regular backup",
      "E) User training"
    ],
    "answer": 0
  },
  {
    "q": "DoS (Denial of Service) saldırısının temel amacı nedir?",
    "options": [
      "A) Hizmetin kullanım dışı bırakılması",
      "B) Veri çalma",
      "C) Sistem yöneticisi olma",
      "D) Şifre kırma",
      "E) Dosya şifreleme"
    ],
    "answer": 0
  },
  {
    "q": "LOIC (Low Orbit Ion Cannon) aracının temel çalışma prensibi nedir?",
    "options": [
      "A) SQL injection gerçekleştirme",
      "B) Hedef sunucuya yoğun HTTP/TCP istekleri gönderme",
      "C) Şifre kırma",
      "D) Ağ trafiği dinleme",
      "E) Dosya şifreleme"
    ],
    "answer": 1
  },
  {
    "q": "SYN Flood saldırısı hangi protokol zafiyetini exploitler?",
    "options": [
      "A) HTTP keep-alive",
      "B) TCP three-way handshake",
      "C) UDP connectionless yapısı",
      "D) ICMP redirect",
      "E) ARP resolution"
    ],
    "answer": 1
  },
  {
    "q": "Hping3 aracı ile SYN flood saldırısı gerçekleştirmek için hangi komut kullanılır?",
    "options": [
      "A) hping3 -S --flood target_ip",
      "B) hping3 -ddos target_ip",
      "C) hping3 -tcp target_ip",
      "D) hping3 -connect target_ip",
      "E) hping3 -syn target_ip"
    ],
    "answer": 0
  },
  {
    "q": "Volumetric DoS saldırısının hedefi nedir?",
    "options": [
      "A) CPU kaynaklarını tüketmek",
      "B) Bellek kaynaklarını tüketmek",
      "C) Bant genişliğini tüketmek",
      "D) Disk alanını doldurmak",
      "E) Veritabanı bağlantılarını tüketmek"
    ],
    "answer": 2
  },
  {
    "q": "Windows sistemlerde SAM (Security Account Manager) dosyası nerede bulunur?",
    "options": [
      "A) C:\\Users",
      "B) C:\\Windows\\System32\\config",
      "C) C:\\Program Files",
      "D) C:\\Temp",
      "E) C:\\Windows\\Logs\\"
    ],
    "answer": 1
  },
  {
    "q": "Linux sistemlerde parola hash'leri hangi dosyada saklanır?",
    "options": [
      "A) /etc/passwd",
      "B) /etc/shadow",
      "C) /etc/group",
      "D) /var/log/auth.log",
      "E) /home/users"
    ],
    "answer": 1
  },
  {
    "q": "Persistence (kalıcılık) sağlamak için hangi yöntem kullanılmaz?",
    "options": [
      "A) Registry değişiklikleri",
      "B) Scheduled task oluşturma",
      "C) Service kurulumu",
      "D) Startup folder'a dosya koyma",
      "E) Sistem saatini değiştirme"
    ],
    "answer": 4
  },
  {
    "q": "Backdoor kurmanın temel amacı nedir?",
    "options": [
      "A) Sistem performansını artırmak",
      "B) Gelecekte erişim için gizli kapı bırakmak",
      "C) Dosyaları yedeklemek",
      "D) Ağ hızını artırmak",
      "E) Güvenlik güncellemesi yapmak"
    ],
    "answer": 1
  },
  {
    "q": "Exfiltration (veri çıkarma) işlemi sırasında dikkat edilmesi gereken en önemli faktör nedir?",
    "options": [
      "A) Transfer hızı",
      "B) Dosya boyutu",
      "C) Gizlilik ve tespit edilmeme",
      "D) İnternet bağlantısı",
      "E) Disk alanı"
    ],
    "answer": 2
  },
  {
    "q": "Aşağıdakilerden hangisi kablosuz ağlarda kaba kuvvet saldırılarına karşı alınabilecek bir önlem değildir?",
    "options": [
      "A) Karmaşık ve uzun parola kullanmak",
      "B) Başarısız oturum açma denemelerinde zaman aşımı uygulamak",
      "C) MAC adres filtrelemesi yapmak",
      "D) SSID yayınını kapatmak",
      "E) WEP şifreleme protokolünü tercih etmek"
    ],
    "answer": 4
  },
  {
    "q": "Kablosuz ağ güvenlik protokollerinin doğru kronolojik sıralaması hangisidir?",
    "options": [
      "A) WPA2 - WPA3 - WEP - WPA",
      "B) WEP - WPA - WPA2 - WPA3",
      "C) WPA - WEP - WPA2 - WPA3",
      "D) WEP - WPA2 - WPA - WPA3",
      "E) WPA - WPA2 - WEP - WPA3"
    ],
    "answer": 1
  },
  {
    "q": "Evil Twin\" saldırısı nedir?",
    "options": [
      "A) İki kablosuz ağın frekans çakışması yaşaması",
      "B) Saldırganın, meşru bir ağın aynısını taklit eden sahte bir erişim noktası oluşturması",
      "C) Ağ trafiğinin iki farklı yönlendiriciye bölünmesi",
      "D) İki farklı cihazın aynı MAC adresini kullanması",
      "E) Bir kablosuz ağı karıştırmak için iki güçlü sinyal jeneratörü kullanılması"
    ],
    "answer": 1
  },
  {
    "q": "Kablosuz ağlarda \"Deauthentication Attack\" (Kimlik doğrulama engelleme saldırısı) için aşağıdakilerden hangisi doğrudur?",
    "options": [
      "A) Kullanıcıların ağa bağlanmasını engellemek için DNS sunucularına yapılan saldırı türüdür",
      "B) Ağ cihazları arasındaki TCP bağlantılarını koparmak için kullanılan bir saldırı türüdür",
      "C) Kimlik doğrulama sunucusunun çalışmasını engelleyen bir DoS saldırısıdır",
      "D) Erişim noktasından istemci cihazlara sahte kimlik doğrulama kaldırma (deauthentication) paketleri göndererek bağlantılarını koparan bir saldırı türüdür",
      "E) Kullanıcıların kimlik bilgilerini ele geçirmek için RADIUS sunucularına yapılan bir saldırı türüdür"
    ],
    "answer": 3
  },
  {
    "q": "Kablosuz ağlarda \"Packet Sniffing\" (Paket koklama) nedir?",
    "options": [
      "A) Ağ üzerindeki paketlerin boyutlarının analiz edilmesi",
      "B) Ağ üzerindeki veri trafiğinin izlenmesi ve kaydedilmesi",
      "C) Paketlerin iletim hızının ölçülmesi",
      "D) Yalnızca bozuk paketlerin tespit edilmesi",
      "E) Sadece belirli IP adreslerine giden paketlerin filtrelenmesi"
    ],
    "answer": 1
  },
  {
    "q": "Steganografi nedir?",
    "options": [
      "A) Şifreleme algoritması",
      "B) Gizli mesajları başka medya içinde saklama sanatı",
      "C) Ağ protokolü",
      "D) Antivirüs tekniği",
      "E) Intrusion detection sistemi"
    ],
    "answer": 1
  },
  {
    "q": "LSB (Least Significant Bit) steganografi yönteminde neye odaklanılır?",
    "options": [
      "A) Dosya başlığına",
      "B) En önemli bitlere",
      "C) En önemsiz bitlere",
      "D) Dosya boyutuna",
      "E) Metadata bilgilerine"
    ],
    "answer": 2
  },
  {
    "q": "Salt değeri hash fonksiyonlarında neden kullanılır?",
    "options": [
      "A) Hash'i hızlandırmak için",
      "B) Rainbow table saldırılarından korunmak için",
      "C) Dosya boyutunu küçültmek için",
      "D) Şifreleme gücünü artırmak için",
      "E) Bellek kullanımını azaltmak için"
    ],
    "answer": 1
  },
  {
    "q": "Hybrid cryptosystem nedir?",
    "options": [
      "A) Sadece simetrik şifreleme",
      "B) Sadece asimetrik şifreleme",
      "C) Simetrik ve asimetrik şifrelemenin birlikte kullanımı",
      "D) Sadece hash fonksiyonları",
      "E) Sadece steganografi"
    ],
    "answer": 2
  },
  {
    "q": "Perfect Forward Secrecy (PFS) özelliği neyi sağlar?",
    "options": [
      "A) Şifrelerin asla kırılmamasını",
      "B) Geçmiş oturumların uzun dönem anahtarlar ele geçirilse bile güvenli kalmasını",
      "C) Sınırsız anahtar uzunluğunu",
      "D) Otomatik anahtar güncellemesini",
      "E) Quantum dayanıklılığını"
    ],
    "answer": 1
  },
  {
    "q": "MITM saldırısının temel konsepti nedir?",
    "options": [
      "A) Sadece dinleme yapma",
      "B) İki taraf arasında gizlice konumlanma",
      "C) Sistemi çökertme",
      "D) Dosyaları şifreleme",
      "E) Hesapları kilitleme"
    ],
    "answer": 1
  },
  {
    "q": "SSL Stripping saldırısının amacı nedir?",
    "options": [
      "A) SSL sertifikalarını silme",
      "B) HTTPS bağlantılarını HTTP'ye düşürme",
      "C) SSL anahtarlarını çalma",
      "D) SSL protokolünü güncelleme",
      "E) SSL hızını artırma"
    ],
    "answer": 1
  },
  {
    "q": "DNS Spoofing saldırısında ne manipüle edilir?",
    "options": [
      "A) IP adresleri",
      "B) DNS yanıtları",
      "C) MAC adresleri",
      "D) Port numaraları",
      "E) Protokol başlıkları"
    ],
    "answer": 1
  },
  {
    "q": "Session Hijacking saldırısında neyin ele geçirilmesi hedeflenir?",
    "options": [
      "A) Kullanıcı parolaları",
      "B) Oturum kimlik bilgileri (session tokens)",
      "C) Sistem dosyaları",
      "D) Ağ ayarları",
      "E) Güvenlik politikaları"
    ],
    "answer": 1
  },
  {
    "q": "MITM saldırılarından korunmanın en etkili yolu nedir?",
    "options": [
      "A) Güçlü parolalar",
      "B) End-to-end encryption ve certificate pinning",
      "C) Antivirüs yazılımı",
      "D) Firewall kuralları",
      "E) Regular backup"
    ],
    "answer": 1
  },
  {
    "q": "MAC Flooding saldırısının temel amacı nedir?",
    "options": [
      "A) Router tablosunu doldurmak",
      "B) Switch'in MAC adres tablosunu doldurmak",
      "C) ARP tablosunu temizlemek",
      "D) DNS cache'ini bozmak",
      "E) DHCP pool'unu tüketmek"
    ],
    "answer": 1
  },
  {
    "q": "MAC Flooding saldırısı sonucunda switch hangi moda geçer?",
    "options": [
      "A) Routing mode",
      "B) Bridge mode",
      "C) Hub mode (fail-open)",
      "D) Security mode",
      "E) Monitor mode"
    ],
    "answer": 2
  },
  {
    "q": "MAC Flooding saldırısında hangi bilgi manipüle edilir?",
    "options": [
      "A) IP adresleri",
      "B) Port numaraları",
      "C) MAC adresleri",
      "D) VLAN ID'leri",
      "E) Subnet mask'leri"
    ],
    "answer": 2
  },
  {
    "q": "Hangi araç MAC Flooding saldırısı gerçekleştirmek için kullanılabilir?",
    "options": [
      "A) Nmap",
      "B) Macof",
      "C) Wireshark",
      "D) Netstat",
      "E) Ping"
    ],
    "answer": 1
  },
  {
    "q": "MAC Flooding saldırısından korunmanın en etkili yolu nedir?",
    "options": [
      "A) VLAN segmentasyonu",
      "B) Port security aktifleştirmek",
      "C) Güçlü parolalar kullanmak",
      "D) Firewall kuralları",
      "E) IDS/IPS sistemleri"
    ],
    "answer": 1
  },
  {
    "q": "WAF (Web Application Firewall) hangi saldırılara karşı koruma sağlar?",
    "options": [
      "A) Sadece DoS saldırıları",
      "B) SQL Injection, XSS, CSRF gibi web tabanlı saldırılar",
      "C) Sadece DDoS saldırıları",
      "D) Sadece malware",
      "E) Sadece ağ tabanlı saldırılar"
    ],
    "answer": 1
  },
  {
    "q": "Input validation hangi saldırı türlerine karşı koruma sağlar?",
    "options": [
      "A) Sadece DoS saldırıları",
      "B) SQL Injection, XSS, Command Injection",
      "C) Sadece ağ saldırıları",
      "D) Sadece malware",
      "E) Sadece social engineering"
    ],
    "answer": 1
  },
  {
    "q": "Honeypot sisteminin amacı nedir?",
    "options": [
      "A) Sistem performansını artırma",
      "B) Saldırıları çekme ve analiz etme",
      "C) Dosyaları yedekleme",
      "D) Ağ hızını artırma",
      "E) Kullanıcı authentication"
    ],
    "answer": 1
  },
  {
    "q": "DDoS scrubbing center nedir?",
    "options": [
      "A) Log temizleme merkezi",
      "B) Kötü amaçlı trafiği filtreleyerek temiz trafiği ileten merkez",
      "C) Virus temizlik merkezi",
      "D) Database optimizasyon merkezi",
      "E) Sistem güncelleme merkezi"
    ],
    "answer": 1
  },
  {
    "q": "CAPTCHA sisteminin temel amacı nedir?",
    "options": [
      "A) Parolaları güçlendirme",
      "B) İnsan ve bot trafiğini ayırt etme",
      "C) Dosyaları şifreleme",
      "D) Ağ bağlantısını hızlandırma",
      "E) Session güvenliğini artırma"
    ],
    "answer": 1
  },
  {
    "q": "IEEE 802.11 standardında tanımlanan \"Beacon Frame\" (İşaret Çerçevesi) hakkında aşağıdakilerden hangisi doğrudur?",
    "options": [
      "A) Sadece istemci cihazlar tarafından gönderilir",
      "B) Erişim noktasının özelliklerini ve varlığını duyurmak için periyodik olarak gönderilir",
      "C) Ağ trafiğini şifrelemek için kullanılır",
      "D) Kullanıcıları kimlik doğrulama işlemi için kullanılır",
      "E) Sadece ağ yöneticileri tarafından manuel olarak tetiklendiğinde gönderilir"
    ],
    "answer": 1
  },
  {
    "q": "Kablosuz ağlarda \"Monitor Mode\" (İzleme Modu) ne işe yarar?",
    "options": [
      "A) Kablosuz ağ kartının sadece bağlı olduğu erişim noktasındaki trafiği izlemesini sağlar",
      "B) Kablosuz ağ kartının sadece kendisine gelen paketleri yakalamasını sağlar",
      "C) Kablosuz ağ kartının tüm kablosuz paketleri yakalamasını sağlar, kendisine yönelik olmasa bile",
      "D) Kablosuz ağ kartının yalnızca yönetim çerçevelerini (management frames) yakalamasını sağlar",
      "E) Kablosuz ağ kartının enerji tasarrufu yapmasını sağlar"
    ],
    "answer": 2
  },
  {
    "q": "Altyapı çalışma modeli (Infrastructure Mode) ile ilgili aşağıdakilerden hangisi yanlıştır?",
    "options": [
      "A) Tüm iletişim erişim noktası (access point) üzerinden gerçekleşir",
      "B) Cihazlar birbirleriyle doğrudan iletişim kurabilir, erişim noktasına gerek yoktur",
      "C) En yaygın kullanılan kablosuz ağ çalışma modelidir",
      "D) BSS (Basic Service Set) veya ESS (Extended Service Set) yapısında çalışır",
      "E) Cihazlar bir SSID'ye bağlanarak ağa dahil olurlar"
    ],
    "answer": 1
  },
  {
    "q": "Kablosuz ağa bağlanma aşamaları sırasıyla nasıldır?",
    "options": [
      "A) Kimlik doğrulama, tarama, ilişkilendirme, veri transferi",
      "B) Tarama, kimlik doğrulama, ilişkilendirme, veri transferi",
      "C) İlişkilendirme, tarama, kimlik doğrulama, veri transferi",
      "D) Tarama, ilişkilendirme, veri transferi, kimlik doğrulama",
      "E) Veri transferi, tarama, kimlik doğrulama, ilişkilendirme"
    ],
    "answer": 1
  },
  {
    "q": "Kablosuz ağ kartlarının çalışma modları arasında aşağıdakilerden hangisi yer almaz?",
    "options": [
      "A) Master Mode",
      "B) Managed Mode",
      "C) Monitor Mode",
      "D) Ad-Hoc Mode",
      "E) Terminal Mode"
    ],
    "answer": 4
  },
  {
    "q": "MD5 hash fonksiyonunun çıktı boyutu kaçtır?",
    "options": [
      "A) 128 bit",
      "B) 160 bit",
      "C) 256 bit",
      "D) 512 bit",
      "E) 64 bit"
    ],
    "answer": 0
  },
  {
    "q": "RSA şifreleme yönteminde güvenlik neye dayanır?",
    "options": [
      "A) Büyük asal sayıların çarpım faktörlerini bulmanın zorluğu",
      "B) Hash fonksiyonlarının geri dönüşümsüzlüğü",
      "C) Simetrik anahtarların gizliliği",
      "D) Quantum hesaplamanın imkansızlığı",
      "E) Digital signature algoritmalarının karmaşıklığı"
    ],
    "answer": 0
  },
  {
    "q": "Diffie-Hellman anahtar değişimin temel amacı nedir?",
    "options": [
      "A) Veriyi şifrelemek",
      "B) Digital signature oluşturmak",
      "C) Güvenli kanal üzerinden anahtar paylaşmak",
      "D) Hash değeri hesaplamak",
      "E) Sertifika doğrulamak"
    ],
    "answer": 2
  },
  {
    "q": "SHA-256 hash fonksiyonunun çıktı boyutu kaçtır?",
    "options": [
      "A) 128 bit",
      "B) 160 bit",
      "C) 256 bit",
      "D) 512 bit",
      "E) 1024 bit"
    ],
    "answer": 2
  },
  {
    "q": "Public Key Infrastructure (PKI) sisteminde sertifikaları kim imzalar?",
    "options": [
      "A) Son kullanıcı",
      "B) Certificate Authority (CA)",
      "C) Web sunucusu",
      "D) DNS sunucusu",
      "E) Proxy server"
    ],
    "answer": 1
  },
  {
    "q": "Wireshark aracının temel işlevi nedir?",
    "options": [
      "A) Ağ trafiğini yakalamak ve analiz etmek",
      "B) Sistem güncellemelerini yapmak",
      "C) Dosyaları şifrelemek",
      "D) Parolaları hashlemek",
      "E) Sistem performansını ölçmek"
    ],
    "answer": 0
  },
  {
    "q": "Tcpdump aracında hangi parametre belirli bir porta gelen trafiği filtrelemek için kullanılır?",
    "options": [
      "A) -i interface",
      "B) -n (no name resolution)",
      "C) -c count",
      "D) port [port_number]",
      "E) -w write"
    ],
    "answer": 3
  },
  {
    "q": "Wireshark'ta display filter olarak hangi ifade HTTP trafiğini gösterir?",
    "options": [
      "A) tcp.port == 80",
      "B) http",
      "C) ip.proto == 6",
      "D) tcp && port 80",
      "E) http.request"
    ],
    "answer": 1
  },
  {
    "q": "Promiscuous mode ne anlama gelir?",
    "options": [
      "A) Sadece kendi trafiğini dinlemek",
      "B) Tüm ağ trafiğini dinlemek",
      "C) Sadece hatalı paketleri yakalamak",
      "D) Sadece encrypted trafiği yakalamak",
      "E) Sadece broadcast paketlerini dinlemek"
    ],
    "answer": 1
  },
  {
    "q": "Tcpdump ile yakalanan trafiği dosyaya kaydetmek için hangi parametre kullanılır?",
    "options": [
      "A) -r filename",
      "B) -w filename",
      "C) -o filename",
      "D) -s filename",
      "E) -f filename"
    ],
    "answer": 1
  },
  {
    "q": "Simetrik şifrelemenin temel özelliği nedir?",
    "options": [
      "A) Şifreleme ve çözme için farklı anahtarlar kullanır",
      "B) Şifreleme ve çözme için aynı anahtar kullanır",
      "C) Anahtar gerektirmez",
      "D) Sadece hash fonksiyonu kullanır",
      "E) Sadece digital signature için kullanılır"
    ],
    "answer": 1
  },
  {
    "q": "DES (Data Encryption Standard) kaç bitlik anahtar kullanır?",
    "options": [
      "A) 128 bit",
      "B) 256 bit",
      "C) 56 bit",
      "D) 64 bit",
      "E) 32 bit"
    ],
    "answer": 2
  },
  {
    "q": "Simetrik şifrelemenin ana dezavantajı nedir?",
    "options": [
      "A) Yavaş çalışması",
      "B) Anahtar dağıtımı problemi",
      "C) Yüksek CPU kullanımı",
      "D) Sadece küçük dosyalarla çalışması",
      "E) Geri dönüşü olmayan şifreleme"
    ],
    "answer": 1
  },
  {
    "q": "AES (Advanced Encryption Standard) hangi anahtar boyutlarını destekler?",
    "options": [
      "A) Sadece 128 bit",
      "B) 128, 192, 256 bit",
      "C) Sadece 256 bit",
      "D) 64, 128 bit",
      "E) 512, 1024 bit"
    ],
    "answer": 1
  },
  {
    "q": "Blowfish şifreleme algoritmasının maksimum anahtar boyutu kaçtır?",
    "options": [
      "A) 128 bit",
      "B) 256 bit",
      "C) 448 bit",
      "D) 512 bit",
      "E) 1024 bit"
    ],
    "answer": 2
  },
  {
    "q": "Windows Event Log'larını temizlemek için hangi komut kullanılır?",
    "options": [
      "A) del eventlog",
      "B) wevtutil cl",
      "C) clear-log",
      "D) remove-event",
      "E) clean-logs"
    ],
    "answer": 1
  },
  {
    "q": "Sızma testi raporunda bulunması gereken temel bileşenler nelerdir?",
    "options": [
      "A) Sadece bulunan zafiyetler",
      "B) Sadece kullanılan araçlar",
      "C) Uygulama özeti, metodoloji, bulgular, öneriler",
      "D) Sadece risk değerlendirmesi",
      "E) Sadece teknik detaylar"
    ],
    "answer": 2
  },
  {
    "q": "CVSS (Common Vulnerability Scoring System) skorlaması neyi ölçer?",
    "options": [
      "A) Sistem performansını",
      "B) Zafiyet ciddiyetini",
      "C) Ağ hızını",
      "D) Kullanıcı memnuniyetini",
      "E) Maliyet analizi"
    ],
    "answer": 1
  },
  {
    "q": "Log analizi sırasında hangi bilgiler aranmalıdır?",
    "options": [
      "A) Başarısız giriş denemeleri",
      "B) Sistem değişiklikleri",
      "C) Unusual network activity",
      "D) Dosya erişimleri",
      "E) Hepsi"
    ],
    "answer": 4
  },
  {
    "q": "Remediation (düzeltme) önerilerinin öncelik sırası hangi kritere göre belirlenir?",
    "options": [
      "A) Düzeltme maliyeti",
      "B) Risk seviyesi ve iş kritikliği",
      "C) Teknik zorluk",
      "D) Zaman kısıtı",
      "E) Personel sayısı"
    ],
    "answer": 1
  },
  {
    "q": "DDoS saldırısının DoS saldırısından temel farkı nedir?",
    "options": [
      "A) Daha güçlü araçlar kullanması",
      "B) Çoklu kaynaklardan eşzamanlı saldırı",
      "C) Farklı protokoller kullanması",
      "D) Daha uzun sürmesi",
      "E) Daha karmaşık teknikleri"
    ],
    "answer": 1
  },
  {
    "q": "Botnet nedir?",
    "options": [
      "A) Güvenlik yazılımı",
      "B) Kötü amaçlı yazılımla kontrol edilen bilgisayar ağı",
      "C) Ağ izleme aracı",
      "D) Firewall sistemi",
      "E) Antivirus programı"
    ],
    "answer": 1
  },
  {
    "q": "DDoS saldırılarından korunmak için hangi yöntem en etkilidir?",
    "options": [
      "A) Güçlü parolalar",
      "B) Düzenli yedek alma",
      "C) CDN ve DDoS mitigation servisleri",
      "D) Antivirüs yazılımı",
      "E) Sistem güncellemeleri"
    ],
    "answer": 2
  },
  {
    "q": "Reflection/Amplification DDoS saldırısının çalışma prensibi nedir?",
    "options": [
      "A) Hedefin kaynaklarını doğrudan tüketme",
      "B) Üçüncü taraf sunucuları kullanarak trafiği büyütme",
      "C) Ağ protokollerini bozma",
      "D) Sisitem dosyalarını silme",
      "E) Kullanıcı hesaplarını kilitleme"
    ],
    "answer": 1
  },
  {
    "q": "Rate limiting nedir?",
    "options": [
      "A) Dosya boyut sınırlaması",
      "B) Belirli bir kaynaktan gelen istek sayısını sınırlama",
      "C) Kullanıcı sayısını sınırlama",
      "D) Bant genişliği sınırlaması",
      "E) Zaman sınırlaması"
    ],
    "answer": 1
  },
  {
    "q": "Brute force saldırısından korunmak için hangi yöntem en etkilidir?",
    "options": [
      "A) Parola karmaşıklığını artırmak",
      "B) Account lockout policy uygulamak",
      "C) Multi-factor authentication",
      "D) Parola geçmişi tutmak",
      "E) Hepsi"
    ],
    "answer": 4
  },
  {
    "q": "Dictionary attack nedir?",
    "options": [
      "A) Kelime anlamlarını değiştirme",
      "B) Yaygın parola listelerini deneme",
      "C) Sözlük dosyalarını şifreleme",
      "D) Dil çevirisi yapma",
      "E) Kelime oyunları oynama"
    ],
    "answer": 1
  },
  {
    "q": "OSINT (Open Source Intelligence) toplamanın temel amacı nedir?",
    "options": [
      "A) Açık kaynak yazılım geliştirmek",
      "B) Halka açık kaynaklardan bilgi toplamak",
      "C) Sosyal medya hesabı açmak",
      "D) Blog yazısı yazmak",
      "E) Online eğitim almak"
    ],
    "answer": 1
  },
  {
    "q": "Rainbow table saldırısında ne kullanılır?",
    "options": [
      "A) Önceden hesaplanmış hash tabloları",
      "B) Renkli grafikler",
      "C) Hava durumu verileri",
      "D) Müzik dosyaları",
      "E) Resim albümleri"
    ],
    "answer": 0
  },
  {
    "q": "Keylogger'ın temel işlevi nedir?",
    "options": [
      "A) Klavye temizleme",
      "B) Klavye tuşlarını kaydetme",
      "C) Klavye hızını ölçme",
      "D) Klavye ışığını ayarlama",
      "E) Klavye sesini açma"
    ],
    "answer": 1
  },
  {
    "q": "SQL Injection saldırısının temel prensibi nedir?",
    "options": [
      "A) Veritabanı şifrelerini kırma",
      "B) SQL sorgularına kötü amaçlı kod enjekte etme",
      "C) Veritabanı dosyalarını silme",
      "D) Ağ trafiğini dinleme",
      "E) Sistem loglarını temizleme"
    ],
    "answer": 1
  },
  {
    "q": "Union-based SQL Injection saldırısinda hangi SQL komutu kullanılır?",
    "options": [
      "A) SELECT",
      "B) INSERT",
      "C) UNION",
      "D) DELETE",
      "E) CREATE"
    ],
    "answer": 2
  },
  {
    "q": "Blind SQL Injection'da saldırgan nasıl bilgi elde eder?",
    "options": [
      "A) Doğrudan veritabanı çıktısından",
      "B) Hata mesajlarından",
      "C) Uygulamanın davranış farklılıklarından",
      "D) Log dosyalarından",
      "E) Sistem bilgilerinden"
    ],
    "answer": 2
  },
  {
    "q": "SQL Injection saldırılarından korunmanın en etkili yolu nedir?",
    "options": [
      "A) Güçlü parolalar",
      "B) Prepared statements/parameterized queries",
      "C) Firewall kullanımı",
      "D) Sistem güncellemeleri",
      "E) Antivirus yazılımı"
    ],
    "answer": 1
  },
  {
    "q": "SQLmap aracının temel işlevi nedir?",
    "options": [
      "A) Veritabanı yedekleme",
      "B) SQL Injection zafiyet tespiti ve sömürme",
      "C) Veritabanı performans analizi",
      "D) SQL sorgu optimizasyonu",
      "E) Veritabanı şifreleme"
    ],
    "answer": 1
  },
  {
    "q": "OWASP Top 10 listesinde sürekli olarak üst sıralarda yer alan web uygulama güvenlik zafiyeti hangisidir?",
    "options": [
      "A) Distributed Denial of Service (DDoS)",
      "B) Broken Access Control",
      "C) Man-in-the-Middle Attack",
      "D) ARP Spoofing",
      "E) MAC Flooding"
    ],
    "answer": 1
  },
  {
    "q": "URL yönlendirme zafiyeti (URL Redirection Vulnerability) için aşağıdaki açıklamalardan hangisi doğrudur?",
    "options": [
      "A) Web sunucusunun yanlış yapılandırılması nedeniyle ortaya çıkan bir zafiyettir",
      "B) Kullanıcının tarayıcısında JavaScript kodlarının çalıştırılmasına izin veren bir zafiyettir",
      "C) Kullanıcının, güvenilir bir web sitesi üzerinden zararlı bir web sitesine yönlendirilmesine neden olan bir zafiyettir",
      "D) Bir web uygulamasının veritabanından bilgi sızdırılmasına yol açan bir zafiyettir",
      "E) Kullanıcının kimlik bilgilerinin web tarayıcısında saklanmasına neden olan bir zafiyettir"
    ],
    "answer": 2
  },
  {
    "q": "HTML Injection zafiyeti ile ilgili aşağıdaki ifadelerden hangisi yanlıştır?",
    "options": [
      "A) Kullanıcı girdileri doğru şekilde filtrelenmediğinde ortaya çıkabilir",
      "B) Sitede görüntülenen içeriği değiştirmek için kullanılabilir",
      "C) Cross-Site Scripting (XSS) saldırılarının bir türüdür",
      "D) Yalnızca HTML etiketlerinin eklenmesine izin verir, JavaScript kodu çalıştırılamaz",
      "E) Sayfanın görünümünü ve içeriğini değiştirerek kullanıcıları kandırmak için kullanılabilir"
    ],
    "answer": 3
  },
  {
    "q": "Web uygulamalarında SQL Injection saldırısına karşı en etkili koruma yöntemi hangisidir?",
    "options": [
      "A) Web Application Firewall (WAF) kullanmak",
      "B) HTTPS protokolünü kullanmak",
      "C) Parametreli sorgular (Prepared Statements) kullanmak",
      "D) Captcha doğrulaması eklemek",
      "E) Kullanıcı oturum süresini kısaltmak"
    ],
    "answer": 2
  },
  {
    "q": "Web uygulamalarında otomatize zafiyet tarama araçları ile ilgili aşağıdakilerden hangisi doğrudur?",
    "options": [
      "A) %100 doğrulukla tüm güvenlik açıklarını tespit edebilirler",
      "B) Yalnızca manuel olarak tespit edilebilen zafiyetleri bulabilirler",
      "C) Yalnızca OWASP Top 10 listesindeki zafiyetleri tarayabilirler",
      "D) Sadece web sunucusu seviyesindeki güvenlik açıklarını tespit edebilirler",
      "E) Birçok zafiyet türünü otomatik olarak tespit edebilirler, ancak manuel doğrulama gerektirebilir"
    ],
    "answer": 4
  },
  {
    "q": "Kablosuz ağlarda veri iletimi hangi yöntemle sağlanır?",
    "options": [
      "A) Sadece fiber optik kablolar üzerinden",
      "B) Elektromanyetik dalgalar aracılığıyla",
      "C) Sadece bakır kablolar üzerinden",
      "D) Sadece koaksiyel kablolar üzerinden",
      "E) Sadece Ethernet kabloları üzerinden"
    ],
    "answer": 1
  },
  {
    "q": "Aşağıdakilerden hangisi bir kablosuz ağ bağlantı çeşidi değildir?",
    "options": [
      "A) WLAN (Wireless Local Area Network)",
      "B) WPAN (Wireless Personal Area Network)",
      "C) WMAN (Wireless Metropolitan Area Network)",
      "D) WWAN (Wireless Wide Area Network)",
      "E) WCAN (Wireless Cable Area Network)"
    ],
    "answer": 4
  },
  {
    "q": "IEEE 802.11 standardının en yaygın kullanılan versiyonu hangisidir?",
    "options": [
      "A) IEEE 802.11a",
      "B) IEEE 802.11b",
      "C) IEEE 802.11g",
      "D) IEEE 802.11n",
      "E) IEEE 802.11ac"
    ],
    "answer": 4
  },
  {
    "q": "Kablosuz ağ güvenlik protokollerinden WPA2 hangi şifreleme algoritmasını kullanır?",
    "options": [
      "A) DES",
      "B) AES",
      "C) MD5",
      "D) RC4",
      "E) SHA-1"
    ],
    "answer": 1
  },
  {
    "q": "Ad-Hoc\" çalışma modu için en doğru tanım hangisidir?",
    "options": [
      "A) Ağ cihazlarının bir erişim noktası üzerinden iletişim kurduğu mod",
      "B) Kablosuz cihazların erişim noktası olmadan doğrudan birbirleriyle iletişim kurduğu mod",
      "C) Kablosuz cihazların sadece kablolu ağlarla iletişim kurduğu mod",
      "D) Erişim noktasının sadece internet bağlantısı sağladığı mod",
      "E) Kablosuz ağın tamamen kapalı olduğu mod"
    ],
    "answer": 1
  },
  {
    "q": "Windows sistemlerde UAC (User Access Control) bypass için hangi yöntem kullanılabilir?",
    "options": [
      "A) Registry değişiklikleri",
      "B) DLL hijacking",
      "C) Token impersonation",
      "D) Service exploitation",
      "E) Hepsi"
    ],
    "answer": 4
  },
  {
    "q": "Windows Local Privilege Escalation için en yaygın kullanılan zafiyet türü hangisidir?",
    "options": [
      "A) Cross-site scripting",
      "B) Unquoted service path",
      "C) DNS spoofing",
      "D) ARP poisoning",
      "E) Session hijacking"
    ],
    "answer": 1
  },
  {
    "q": "Windows Active Directory ortamında Kerberoasting saldırısının amacı nedir?",
    "options": [
      "A) Domain controller'ı çökertmek",
      "B) Servis hesaplarının hash'lerini elde etmek",
      "C) LDAP bağlantısını kesmek",
      "D) DNS cache'ini temizlemek",
      "E) Group Policy'leri değiştirmek"
    ],
    "answer": 1
  },
  {
    "q": "Mimikatz aracının temel işlevi nedir?",
    "options": [
      "A) Port tarama",
      "B) Kimlik bilgilerini bellekten çıkarma",
      "C) Dosya şifreleme",
      "D) Ağ trafiği analizi",
      "E) Sistem güncellemesi"
    ],
    "answer": 1
  },
  {
    "q": "Windows sistemlerde AlwaysInstallElevated zafiyeti ne anlama gelir?",
    "options": [
      "A) Sistem her zaman otomatik güncellenir",
      "B) MSI paketleri her zaman yüksek yetkilerle çalışır",
      "C) Sistem her zaman güvenli modda başlar",
      "D) Firewall her zaman aktiftir",
      "E) Antivirus her zaman çalışır"
    ],
    "answer": 1
  },
  {
    "q": "Sızma testi sırasında erişim elde etmenin ilk aşaması hangisidir?",
    "options": [
      "A) Sistemde backdoor kurulumu",
      "B) Hedef sistemin keşfi ve zafiyet tespiti",
      "C) Yetki yükseltme işlemi",
      "D) Log dosyalarının silinmesi",
      "E) Lateral movement başlatma"
    ],
    "answer": 1
  },
  {
    "q": "Buffer overflow saldırısının temel amacı nedir?",
    "options": [
      "A) Ağ trafiğini izlemek",
      "B) Dosya sistemini şifrelemek",
      "C) Sistem belleğinde kod çalıştırarak kontrol ele geçirmek",
      "D) Kullanıcı parolalarını çalmak",
      "E) Sistem loglarını temizlemek"
    ],
    "answer": 2
  },
  {
    "q": "SQL Injection saldırısında hangi parametre kullanılarak veritabanına erişim sağlanır?",
    "options": [
      "A) HTTP başlıkları",
      "B) Kullanıcı giriş alanları",
      "C) SSL sertifikaları",
      "D) DNS kayıtları",
      "E) ARP tablosu"
    ],
    "answer": 1
  },
  {
    "q": "Phishing saldırısının ana hedefi nedir?",
    "options": [
      "A) Sistem kaynaklarını tüketmek",
      "B) Kullanıcı kimlik bilgilerini çalmak",
      "C) Ağ bağlantısını kesmek",
      "D) Dosyaları şifrelemek",
      "E) Sistem performansını düşürmek"
    ],
    "answer": 1
  },
  {
    "q": "Reverse shell nedir?",
    "options": [
      "A) Hedef sistemin güvenlik duvarını devre dışı bırakma",
      "B) Uzak sistemden saldırganın makinesine bağlantı kurma",
      "C) Dosya sistemini tersine çevirme",
      "D) Şifreli bağlantıyı çözme",
      "E) Sistem saatini geri alma"
    ],
    "answer": 1
  },
  {
    "q": "Kablosuz ağlarda keşif yapma yöntemlerinden hangisi pasif keşif olarak değerlendirilir?",
    "options": [
      "A) Probe Request paketleri göndermek",
      "B) Deauthentication paketleri göndermek",
      "C) Beacon Frame'leri dinlemek",
      "D) ARP paketleri göndermek",
      "E) Ping taraması yapmak"
    ],
    "answer": 2
  },
  {
    "q": "Kablosuz Ağ Saldırı Tespit Sistemleri (WIDS) hakkında aşağıdakilerden hangisi yanlıştır?",
    "options": [
      "A) Yetkisiz erişim noktalarını tespit edebilir",
      "B) MAC spoofing saldırılarını tespit edebilir",
      "C) Deauthentication saldırılarını tespit edebilir",
      "D) Tüm saldırı türlerini %100 doğrulukla tespit edebilir",
      "E) Ağ trafiğini analiz ederek anormal davranışları belirleyebilir"
    ],
    "answer": 3
  },
  {
    "q": "Aşağıdakilerden hangisi kablosuz ağlarda rogue (sahte) erişim noktalarının tespiti için kullanılan bir yöntem değildir?",
    "options": [
      "A) RF fingerprinting analizi",
      "B) Zaman tabanlı analiz",
      "C) Trafik analizi",
      "D) IP adresi bloklama",
      "E) MAC adresi karşılaştırması"
    ],
    "answer": 3
  },
  {
    "q": "Kablosuz ağlarda aktif ve pasif parmak izi toplama (fingerprinting) yöntemleri arasındaki fark nedir?",
    "options": [
      "A) Aktif yöntemler daha hızlıdır, pasif yöntemler daha yavaştır",
      "B) Aktif yöntemler sadece yöneticiler tarafından kullanılabilir, pasif yöntemler herkes tarafından kullanılabilir",
      "C) Aktif yöntemler ağa paket göndererek bilgi toplar, pasif yöntemler sadece dinleme yaparak bilgi toplar",
      "D) Aktif yöntemler sadece erişim noktalarını tespit eder, pasif yöntemler tüm cihazları tespit eder",
      "E) Aktif yöntemler WPA/WPA2 ağlarında, pasif yöntemler sadece WEP ağlarında çalışır"
    ],
    "answer": 2
  },
  {
    "q": "Kablosuz ağ saldırı tespit sistemlerinde \"Anomali Tabanlı Tespit\" yöntemi neye dayanır?",
    "options": [
      "A) Bilinen saldırı imzalarının veritabanına",
      "B) Normal ağ trafiği modelinden sapmaların tespitine",
      "C) Güvenlik duvarı kurallarına",
      "D) Sadece kullanıcı davranışlarının izlenmesine",
      "E) Yalnızca protokol analizine"
    ],
    "answer": 1
  },
  {
    "q": "Web Uygulama Güvenlik Duvarı (WAF) ile ilgili aşağıdakilerden hangisi yanlıştır?",
    "options": [
      "A) HTTP trafiğini izler ve analiz eder",
      "B) SQL Injection ve XSS gibi saldırıları engelleyebilir",
      "C) Doğrudan veritabanı güvenliğini sağlar ve veritabanı üzerindeki tüm saldırıları engeller",
      "D) İmza tabanlı ve davranışsal analiz yöntemlerini kullanabilir",
      "E) Hem donanım hem de yazılım tabanlı çözümleri mevcuttur"
    ],
    "answer": 2
  },
  {
    "q": "Web servislerinin keşfedilmesi için kullanılan yöntemlerden hangisi değildir?",
    "options": [
      "A) WSDL dosyalarının incelenmesi",
      "B) DNS zone transfer saldırıları",
      "C) Dizin tarama araçları kullanma",
      "D) API dokümantasyonlarını inceleme",
      "E) TCP/IP paket analizi yapma"
    ],
    "answer": 4
  },
  {
    "q": "Web uygulama güvenlik duvarlarını (WAF) atlatma teknikleri arasında hangisi yer almaz?",
    "options": [
      "A) HTTP parametre kirliliği (HTTP Parameter Pollution)",
      "B) Kodlama varyasyonları (Encoding Variations)",
      "C) SSL/TLS kullanımı",
      "D) Bölünmüş saldırılar (Fragmented Attacks)",
      "E) HTTP Yöntem değiştirme (HTTP Method Tampering)"
    ],
    "answer": 2
  },
  {
    "q": "Web servislerine yönelik zafiyetlerden \"XML External Entity (XXE)\" saldırısı neyi hedefler?",
    "options": [
      "A) Servis kodlarının çalınmasını",
      "B) Sunucu dosya sistemine erişimi",
      "C) Sadece veritabanı bağlantılarını kesmeyi",
      "D) Sadece hizmet reddi (DoS) saldırısı gerçekleştirmeyi",
      "E) Sadece oturum bilgilerini çalmayı"
    ],
    "answer": 1
  },
  {
    "q": "Web servislerinde REST API güvenliği için aşağıdakilerden hangisi en az önemlidir?",
    "options": [
      "A) API anahtarları ve token tabanlı kimlik doğrulama",
      "B) HTTPS protokolü kullanımı",
      "C) İstek sınırlama (Rate Limiting)",
      "D) CORS (Cross-Origin Resource Sharing) yapılandırması",
      "E) API endpoint'lerin gizli ve tahmin edilemez URL'lere sahip olması"
    ],
    "answer": 4
  },
  {
    "q": "Lateral movement'ın temel amacı nedir?",
    "options": [
      "A) Sistem performansını artırmak",
      "B) Ağ içinde başka sistemlere erişim sağlamak",
      "C) Dosyaları yedeklemek",
      "D) Güvenlik güncellemelerini yapmak",
      "E) Ağ bant genişliğini artırmak"
    ],
    "answer": 1
  },
  {
    "q": "Pass-the-Hash saldırısında ne kullanılır?",
    "options": [
      "A) Şifreli parolalar",
      "B) Hash değerleri",
      "C) SSL sertifikaları",
      "D) MAC adresleri",
      "E) IP adresleri"
    ],
    "answer": 1
  },
  {
    "q": "SMB protokolü üzerinden yapılan lateral movement için hangi araç yaygın kullanılır?",
    "options": [
      "A) Nmap",
      "B) PsExec",
      "C) Wireshark",
      "D) Burp Suite",
      "E) Metasploit Framework"
    ],
    "answer": 1
  },
  {
    "q": "Windows ortamında WMI (Windows Management Instrumentation) lateral movement için nasıl kullanılır?",
    "options": [
      "A) Dosya transferi için",
      "B) Uzak komut çalıştırma için",
      "C) Ağ dinleme için",
      "D) Şifre çözme için",
      "E) Sistem tarama için"
    ],
    "answer": 1
  },
  {
    "q": "Golden Ticket saldırısı hangi protokolü hedefler?",
    "options": [
      "A) HTTP",
      "B) FTP",
      "C) Kerberos",
      "D) SSH",
      "E) SMTP"
    ],
    "answer": 2
  },
  {
    "q": "HULK (HTTP Unbearable Load King) aracının çalışma prensibi nedir?",
    "options": [
      "A) Database kaynaklarını tüketme",
      "B) Benzersiz HTTP istekleri oluşturarak cache bypass",
      "C) Ağ bağlantılarını kesme",
      "D) Sistem belleğini doldurma",
      "E) CPU döngülerini tüketme"
    ],
    "answer": 1
  },
  {
    "q": "OWASP SwitchBlade aracının temel amacı nedir?",
    "options": [
      "A) Güvenlik zafiyet taraması",
      "B) Switch ağlarında DoS saldırısı",
      "C) Web uygulaması testing",
      "D) Sızma testi otomasyonu",
      "E) Kod analizi"
    ],
    "answer": 1
  },
  {
    "q": "Time-based Blind SQL Injection'da hangi teknik kullanılır?",
    "options": [
      "A) Error messages analizi",
      "B) Database response delay",
      "C) Direct output reading",
      "D) HTTP status codes",
      "E) Cookie manipulation"
    ],
    "answer": 1
  },
  {
    "q": "CSRF (Cross-Site Request Forgery) saldırısının hedefi nedir?",
    "options": [
      "A) Kullanıcı parolasını çalma",
      "B) Kullanıcı adına isteksiz işlemler yaptırma",
      "C) Web sitesini çökertme",
      "D) Database'e erişim sağlama",
      "E) Session token'ları çalma"
    ],
    "answer": 1
  },
  {
    "q": "Slowloris saldırısının çalışma prensibi nedir?",
    "options": [
      "A) Büyük dosyalar upload etme",
      "B) Yarım HTTP bağlantılarını uzun süre açık tutma",
      "C) SQL injection gerçekleştirme",
      "D) Cross-site scripting",
      "E) Buffer overflow"
    ],
    "answer": 1
  }


];


document.addEventListener("DOMContentLoaded", () => {
  let currentQuestionIndex = 0;
  let correctCount = 0;
  let userAnswers = [];

  // Soruları karıştırma fonksiyonu
  function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  // Soruları kopyala, karıştır ve 20 tane al
  const questionsCopy = [...questions];
  shuffleArray(questionsCopy);
  const quizQuestions = questionsCopy.slice(0, 20);

  const questionEl = document.getElementById('question');
  const optionsEl = document.getElementById('options');
  const nextBtn = document.getElementById('next');

  function showQuestion() {
    const q = quizQuestions[currentQuestionIndex];
    questionEl.textContent = `Soru ${currentQuestionIndex + 1}: ${q.q}`;

    optionsEl.innerHTML = '';
    q.options.forEach((option, index) => {
      const label = document.createElement('label');
      label.innerHTML = `
        <input type="radio" name="option" value="${index}">
        ${option}
      `;
      optionsEl.appendChild(label);
    });
  }

  function showResult() {
    questionEl.textContent = `Quiz tamamlandı! Doğru sayınız: ${correctCount} / ${quizQuestions.length}`;
    optionsEl.innerHTML = '';

    quizQuestions.forEach((q, i) => {
      const div = document.createElement('div');
      const correctIndex = q.answer;
      const userIndex = userAnswers[i];
      const isCorrect = userIndex == correctIndex;

      div.innerHTML = `
        <strong>Soru ${i + 1}:</strong> ${q.q} <br>
        Doğru Cevap: ${q.options[correctIndex]} <br>
        Senin Cevabın: ${userIndex !== undefined ? q.options[userIndex] : "Cevap verilmedi"} ${isCorrect ? "✅" : "❌"}
        <hr>
      `;
      optionsEl.appendChild(div);
    });

    nextBtn.style.display = 'none';
  }

  nextBtn.addEventListener('click', () => {
    const selected = document.querySelector('input[name="option"]:checked');
    if (!selected) {
      alert('Lütfen bir seçenek işaretleyin!');
      return;
    }

    userAnswers[currentQuestionIndex] = parseInt(selected.value);

    if (parseInt(selected.value) === quizQuestions[currentQuestionIndex].answer) {
      correctCount++;
    }

    currentQuestionIndex++;

    if (currentQuestionIndex < quizQuestions.length) {
      showQuestion();
    } else {
      showResult();
    }
  });

  showQuestion();
});

