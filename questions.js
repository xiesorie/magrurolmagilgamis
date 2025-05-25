document.getElementById("quiz").innerHTML = "<p>Test başarılı</p>";

document.addEventListener("DOMContentLoaded", function() {


const allQuestions = [
    
  {
    "Question": "ARP Poisoning saldırısının temel prensibi nedir?",
    "Option a": "DNS kayıtlarını değiştirmek",
    "Option b": "ARP tablosunda sahte kayıtlar oluşturmak",
    "Option c": "Routing tablosunu bozmak",
    "Option d": "DHCP server'ı çökertmek",
    "Option e": "Firewall kurallarını bypass etmek",
    "Answer": "b"
  },
  {
    "Question": "Man-in-the-Middle saldırısında saldırgan ne yapar?",
    "Option a": "Ağ bağlantısını keser",
    "Option b": "İki taraf arasında gizlice iletişimi dinler/manipüle eder",
    "Option c": "Sadece şifreleri kırır",
    "Option d": "Sistem dosyalarını değiştirir",
    "Option e": "Firewall'ı devre dışı bırakır",
    "Answer": "b"
  },
  {
    "Question": "ARP protokolü hangi OSI katmanında çalışır?",
    "Option a": "Layer 1 (Physical)",
    "Option b": "Layer 2 (Data Link)",
    "Option c": "Layer 3 (Network)",
    "Option d": "Layer 4 (Transport)",
    "Option e": "Layer 7 (Application)",
    "Answer": "b"
  },
  {
    "Question": "Ettercap aracının temel işlevi nedir?",
    "Option a": "Port tarama",
    "Option b": "ARP Poisoning ve MITM saldırıları",
    "Option c": "Dosya şifreleme",
    "Option d": "Sistem yedekleme",
    "Option e": "Network monitoring",
    "Answer": "b"
  },
  {
    "Question": "ARP Poisoning saldırısından korunmanın en etkili yolu nedir?",
    "Option a": "Dynamic ARP Inspection (DAI)",
    "Option b": "Güçlü parolalar",
    "Option c": "Antivirus kullanmak",
    "Option d": "Regular backup",
    "Option e": "User training",
    "Answer": "a"
  },
  {
    "Question": "DoS (Denial of Service) saldırısının temel amacı nedir?",
    "Option a": "Hizmetin kullanım dışı bırakılması",
    "Option b": "Veri çalma",
    "Option c": "Sistem yöneticisi olma",
    "Option d": "Şifre kırma",
    "Option e": "Dosya şifreleme",
    "Answer": "a"
  },
  {
    "Question": "LOIC (Low Orbit Ion Cannon) aracının temel çalışma prensibi nedir?",
    "Option a": "SQL injection gerçekleştirme",
    "Option b": "Hedef sunucuya yoğun HTTP/TCP istekleri gönderme",
    "Option c": "Şifre kırma",
    "Option d": "Ağ trafiği dinleme",
    "Option e": "Dosya şifreleme",
    "Answer": "b"
  },
  {
    "Question": "SYN Flood saldırısı hangi protokol zafiyetini exploitler?",
    "Option a": "HTTP keep-alive",
    "Option b": "TCP three-way handshake",
    "Option c": "UDP connectionless yapısı",
    "Option d": "ICMP redirect",
    "Option e": "ARP resolution",
    "Answer": "b"
  },
  {
    "Question": "Hping3 aracı ile SYN flood saldırısı gerçekleştirmek için hangi komut kullanılır?",
    "Option a": "hping3 -S --flood target_ip",
    "Option b": "hping3 -ddos target_ip",
    "Option c": "hping3 -tcp target_ip",
    "Option d": "hping3 -connect target_ip",
    "Option e": "hping3 -syn target_ip",
    "Answer": "a"
  },
  {
    "Question": "Volumetric DoS saldırısının hedefi nedir?",
    "Option a": "CPU kaynaklarını tüketmek",
    "Option b": "Bellek kaynaklarını tüketmek",
    "Option c": "Bant genişliğini tüketmek",
    "Option d": "Disk alanını doldurmak",
    "Option e": "Veritabanı bağlantılarını tüketmek",
    "Answer": "c"
  },
  {
    "Question": "Windows sistemlerde SAM (Security Account Manager) dosyası nerede bulunur?",
    "Option a": "C:\\Users",
    "Option b": "C:\\Windows\\System32\\config",
    "Option c": "C:\\Program Files",
    "Option d": "C:\\Temp",
    "Option e": "C:\\Windows\\Logs\\",
    "Answer": "b"
  },
  {
    "Question": "Linux sistemlerde parola hash'leri hangi dosyada saklanır?",
    "Option a": "/etc/passwd",
    "Option b": "/etc/shadow",
    "Option c": "/etc/group",
    "Option d": "/var/log/auth.log",
    "Option e": "/home/users",
    "Answer": "b"
  },
  {
    "Question": "Persistence (kalıcılık) sağlamak için hangi yöntem kullanılmaz?",
    "Option a": "Registry değişiklikleri",
    "Option b": "Scheduled task oluşturma",
    "Option c": "Service kurulumu",
    "Option d": "Startup folder'a dosya koyma",
    "Option e": "Sistem saatini değiştirme",
    "Answer": "e"
  },
  {
    "Question": "Backdoor kurmanın temel amacı nedir?",
    "Option a": "Sistem performansını artırmak",
    "Option b": "Gelecekte erişim için gizli kapı bırakmak",
    "Option c": "Dosyaları yedeklemek",
    "Option d": "Ağ hızını artırmak",
    "Option e": "Güvenlik güncellemesi yapmak",
    "Answer": "b"
  },
  {
    "Question": "Exfiltration (veri çıkarma) işlemi sırasında dikkat edilmesi gereken en önemli faktör nedir?",
    "Option a": "Transfer hızı",
    "Option b": "Dosya boyutu",
    "Option c": "Gizlilik ve tespit edilmeme",
    "Option d": "İnternet bağlantısı",
    "Option e": "Disk alanı",
    "Answer": "c"
  },
  {
    "Question": "Aşağıdakilerden hangisi kablosuz ağlarda kaba kuvvet saldırılarına karşı alınabilecek bir önlem değildir?",
    "Option a": "Karmaşık ve uzun parola kullanmak",
    "Option b": "Başarısız oturum açma denemelerinde zaman aşımı uygulamak",
    "Option c": "MAC adres filtrelemesi yapmak",
    "Option d": "SSID yayınını kapatmak",
    "Option e": "WEP şifreleme protokolünü tercih etmek",
    "Answer": "e"
  },
  {
    "Question": "Kablosuz ağ güvenlik protokollerinin doğru kronolojik sıralaması hangisidir?",
    "Option a": "WPA2 - WPA3 - WEP - WPA",
    "Option b": "WEP - WPA - WPA2 - WPA3",
    "Option c": "WPA - WEP - WPA2 - WPA3",
    "Option d": "WEP - WPA2 - WPA - WPA3",
    "Option e": "WPA - WPA2 - WEP - WPA3",
    "Answer": "b"
  },
  {
    "Question": "Evil Twin\" saldırısı nedir?",
    "Option a": "İki kablosuz ağın frekans çakışması yaşaması",
    "Option b": "Saldırganın, meşru bir ağın aynısını taklit eden sahte bir erişim noktası oluşturması",
    "Option c": "Ağ trafiğinin iki farklı yönlendiriciye bölünmesi",
    "Option d": "İki farklı cihazın aynı MAC adresini kullanması",
    "Option e": "Bir kablosuz ağı karıştırmak için iki güçlü sinyal jeneratörü kullanılması",
    "Answer": "b"
  },
  {
    "Question": "Kablosuz ağlarda \"Deauthentication Attack\" (Kimlik doğrulama engelleme saldırısı) için aşağıdakilerden hangisi doğrudur?",
    "Option a": "Kullanıcıların ağa bağlanmasını engellemek için DNS sunucularına yapılan saldırı türüdür",
    "Option b": "Ağ cihazları arasındaki TCP bağlantılarını koparmak için kullanılan bir saldırı türüdür",
    "Option c": "Kimlik doğrulama sunucusunun çalışmasını engelleyen bir DoS saldırısıdır",
    "Option d": "Erişim noktasından istemci cihazlara sahte kimlik doğrulama kaldırma (deauthentication) paketleri göndererek bağlantılarını koparan bir saldırı türüdür",
    "Option e": "Kullanıcıların kimlik bilgilerini ele geçirmek için RADIUS sunucularına yapılan bir saldırı türüdür",
    "Answer": "d"
  },
  {
    "Question": "Kablosuz ağlarda \"Packet Sniffing\" (Paket koklama) nedir?",
    "Option a": "Ağ üzerindeki paketlerin boyutlarının analiz edilmesi",
    "Option b": "Ağ üzerindeki veri trafiğinin izlenmesi ve kaydedilmesi",
    "Option c": "Paketlerin iletim hızının ölçülmesi",
    "Option d": "Yalnızca bozuk paketlerin tespit edilmesi",
    "Option e": "Sadece belirli IP adreslerine giden paketlerin filtrelenmesi",
    "Answer": "b"
  },
  {
    "Question": "Steganografi nedir?",
    "Option a": "Şifreleme algoritması",
    "Option b": "Gizli mesajları başka medya içinde saklama sanatı",
    "Option c": "Ağ protokolü",
    "Option d": "Antivirüs tekniği",
    "Option e": "Intrusion detection sistemi",
    "Answer": "b"
  },
  {
    "Question": "LSB (Least Significant Bit) steganografi yönteminde neye odaklanılır?",
    "Option a": "Dosya başlığına",
    "Option b": "En önemli bitlere",
    "Option c": "En önemsiz bitlere",
    "Option d": "Dosya boyutuna",
    "Option e": "Metadata bilgilerine",
    "Answer": "c"
  },
  {
    "Question": "Salt değeri hash fonksiyonlarında neden kullanılır?",
    "Option a": "Hash'i hızlandırmak için",
    "Option b": "Rainbow table saldırılarından korunmak için",
    "Option c": "Dosya boyutunu küçültmek için",
    "Option d": "Şifreleme gücünü artırmak için",
    "Option e": "Bellek kullanımını azaltmak için",
    "Answer": "b"
  },
  {
    "Question": "Hybrid cryptosystem nedir?",
    "Option a": "Sadece simetrik şifreleme",
    "Option b": "Sadece asimetrik şifreleme",
    "Option c": "Simetrik ve asimetrik şifrelemenin birlikte kullanımı",
    "Option d": "Sadece hash fonksiyonları",
    "Option e": "Sadece steganografi",
    "Answer": "c"
  },
  {
    "Question": "Perfect Forward Secrecy (PFS) özelliği neyi sağlar?",
    "Option a": "Şifrelerin asla kırılmamasını",
    "Option b": "Geçmiş oturumların uzun dönem anahtarlar ele geçirilse bile güvenli kalmasını",
    "Option c": "Sınırsız anahtar uzunluğunu",
    "Option d": "Otomatik anahtar güncellemesini",
    "Option e": "Quantum dayanıklılığını",
    "Answer": "b"
  },
  {
    "Question": "MITM saldırısının temel konsepti nedir?",
    "Option a": "Sadece dinleme yapma",
    "Option b": "İki taraf arasında gizlice konumlanma",
    "Option c": "Sistemi çökertme",
    "Option d": "Dosyaları şifreleme",
    "Option e": "Hesapları kilitleme",
    "Answer": "b"
  },
  {
    "Question": "SSL Stripping saldırısının amacı nedir?",
    "Option a": "SSL sertifikalarını silme",
    "Option b": "HTTPS bağlantılarını HTTP'ye düşürme",
    "Option c": "SSL anahtarlarını çalma",
    "Option d": "SSL protokolünü güncelleme",
    "Option e": "SSL hızını artırma",
    "Answer": "b"
  },
  {
    "Question": "DNS Spoofing saldırısında ne manipüle edilir?",
    "Option a": "IP adresleri",
    "Option b": "DNS yanıtları",
    "Option c": "MAC adresleri",
    "Option d": "Port numaraları",
    "Option e": "Protokol başlıkları",
    "Answer": "b"
  },
  {
    "Question": "Session Hijacking saldırısında neyin ele geçirilmesi hedeflenir?",
    "Option a": "Kullanıcı parolaları",
    "Option b": "Oturum kimlik bilgileri (session tokens)",
    "Option c": "Sistem dosyaları",
    "Option d": "Ağ ayarları",
    "Option e": "Güvenlik politikaları",
    "Answer": "b"
  },
  {
    "Question": "MITM saldırılarından korunmanın en etkili yolu nedir?",
    "Option a": "Güçlü parolalar",
    "Option b": "End-to-end encryption ve certificate pinning",
    "Option c": "Antivirüs yazılımı",
    "Option d": "Firewall kuralları",
    "Option e": "Regular backup",
    "Answer": "b"
  },
  {
    "Question": "MAC Flooding saldırısının temel amacı nedir?",
    "Option a": "Router tablosunu doldurmak",
    "Option b": "Switch'in MAC adres tablosunu doldurmak",
    "Option c": "ARP tablosunu temizlemek",
    "Option d": "DNS cache'ini bozmak",
    "Option e": "DHCP pool'unu tüketmek",
    "Answer": "b"
  },
  {
    "Question": "MAC Flooding saldırısı sonucunda switch hangi moda geçer?",
    "Option a": "Routing mode",
    "Option b": "Bridge mode",
    "Option c": "Hub mode (fail-open)",
    "Option d": "Security mode",
    "Option e": "Monitor mode",
    "Answer": "c"
  },
  {
    "Question": "MAC Flooding saldırısında hangi bilgi manipüle edilir?",
    "Option a": "IP adresleri",
    "Option b": "Port numaraları",
    "Option c": "MAC adresleri",
    "Option d": "VLAN ID'leri",
    "Option e": "Subnet mask'leri",
    "Answer": "c"
  },
  {
    "Question": "Hangi araç MAC Flooding saldırısı gerçekleştirmek için kullanılabilir?",
    "Option a": "Nmap",
    "Option b": "Macof",
    "Option c": "Wireshark",
    "Option d": "Netstat",
    "Option e": "Ping",
    "Answer": "b"
  },
  {
    "Question": "MAC Flooding saldırısından korunmanın en etkili yolu nedir?",
    "Option a": "VLAN segmentasyonu",
    "Option b": "Port security aktifleştirmek",
    "Option c": "Güçlü parolalar kullanmak",
    "Option d": "Firewall kuralları",
    "Option e": "IDS/IPS sistemleri",
    "Answer": "b"
  },
  {
    "Question": "WAF (Web Application Firewall) hangi saldırılara karşı koruma sağlar?",
    "Option a": "Sadece DoS saldırıları",
    "Option b": "SQL Injection, XSS, CSRF gibi web tabanlı saldırılar",
    "Option c": "Sadece DDoS saldırıları",
    "Option d": "Sadece malware",
    "Option e": "Sadece ağ tabanlı saldırılar",
    "Answer": "b"
  },
  {
    "Question": "Input validation hangi saldırı türlerine karşı koruma sağlar?",
    "Option a": "Sadece DoS saldırıları",
    "Option b": "SQL Injection, XSS, Command Injection",
    "Option c": "Sadece ağ saldırıları",
    "Option d": "Sadece malware",
    "Option e": "Sadece social engineering",
    "Answer": "b"
  },
  {
    "Question": "Honeypot sisteminin amacı nedir?",
    "Option a": "Sistem performansını artırma",
    "Option b": "Saldırıları çekme ve analiz etme",
    "Option c": "Dosyaları yedekleme",
    "Option d": "Ağ hızını artırma",
    "Option e": "Kullanıcı authentication",
    "Answer": "b"
  },
  {
    "Question": "DDoS scrubbing center nedir?",
    "Option a": "Log temizleme merkezi",
    "Option b": "Kötü amaçlı trafiği filtreleyerek temiz trafiği ileten merkez",
    "Option c": "Virus temizlik merkezi",
    "Option d": "Database optimizasyon merkezi",
    "Option e": "Sistem güncelleme merkezi",
    "Answer": "b"
  },
  {
    "Question": "CAPTCHA sisteminin temel amacı nedir?",
    "Option a": "Parolaları güçlendirme",
    "Option b": "İnsan ve bot trafiğini ayırt etme",
    "Option c": "Dosyaları şifreleme",
    "Option d": "Ağ bağlantısını hızlandırma",
    "Option e": "Session güvenliğini artırma",
    "Answer": "b"
  },
  {
    "Question": "IEEE 802.11 standardında tanımlanan \"Beacon Frame\" (İşaret Çerçevesi) hakkında aşağıdakilerden hangisi doğrudur?",
    "Option a": "Sadece istemci cihazlar tarafından gönderilir",
    "Option b": "Erişim noktasının özelliklerini ve varlığını duyurmak için periyodik olarak gönderilir",
    "Option c": "Ağ trafiğini şifrelemek için kullanılır",
    "Option d": "Kullanıcıları kimlik doğrulama işlemi için kullanılır",
    "Option e": "Sadece ağ yöneticileri tarafından manuel olarak tetiklendiğinde gönderilir",
    "Answer": "b"
  },
  {
    "Question": "Kablosuz ağlarda \"Monitor Mode\" (İzleme Modu) ne işe yarar?",
    "Option a": "Kablosuz ağ kartının sadece bağlı olduğu erişim noktasındaki trafiği izlemesini sağlar",
    "Option b": "Kablosuz ağ kartının sadece kendisine gelen paketleri yakalamasını sağlar",
    "Option c": "Kablosuz ağ kartının tüm kablosuz paketleri yakalamasını sağlar, kendisine yönelik olmasa bile",
    "Option d": "Kablosuz ağ kartının yalnızca yönetim çerçevelerini (management frames) yakalamasını sağlar",
    "Option e": "Kablosuz ağ kartının enerji tasarrufu yapmasını sağlar",
    "Answer": "c"
  },
  {
    "Question": "Altyapı çalışma modeli (Infrastructure Mode) ile ilgili aşağıdakilerden hangisi yanlıştır?",
    "Option a": "Tüm iletişim erişim noktası (access point) üzerinden gerçekleşir",
    "Option b": "Cihazlar birbirleriyle doğrudan iletişim kurabilir, erişim noktasına gerek yoktur",
    "Option c": "En yaygın kullanılan kablosuz ağ çalışma modelidir",
    "Option d": "BSS (Basic Service Set) veya ESS (Extended Service Set) yapısında çalışır",
    "Option e": "Cihazlar bir SSID'ye bağlanarak ağa dahil olurlar",
    "Answer": "b"
  },
  {
    "Question": "Kablosuz ağa bağlanma aşamaları sırasıyla nasıldır?",
    "Option a": "Kimlik doğrulama, tarama, ilişkilendirme, veri transferi",
    "Option b": "Tarama, kimlik doğrulama, ilişkilendirme, veri transferi",
    "Option c": "İlişkilendirme, tarama, kimlik doğrulama, veri transferi",
    "Option d": "Tarama, ilişkilendirme, veri transferi, kimlik doğrulama",
    "Option e": "Veri transferi, tarama, kimlik doğrulama, ilişkilendirme",
    "Answer": "b"
  },
  {
    "Question": "Kablosuz ağ kartlarının çalışma modları arasında aşağıdakilerden hangisi yer almaz?",
    "Option a": "Master Mode",
    "Option b": "Managed Mode",
    "Option c": "Monitor Mode",
    "Option d": "Ad-Hoc Mode",
    "Option e": "Terminal Mode",
    "Answer": "e"
  },
  {
    "Question": "MD5 hash fonksiyonunun çıktı boyutu kaçtır?",
    "Option a": "128 bit",
    "Option b": "160 bit",
    "Option c": "256 bit",
    "Option d": "512 bit",
    "Option e": "64 bit",
    "Answer": "a"
  },
  {
    "Question": "RSA şifreleme yönteminde güvenlik neye dayanır?",
    "Option a": "Büyük asal sayıların çarpım faktörlerini bulmanın zorluğu",
    "Option b": "Hash fonksiyonlarının geri dönüşümsüzlüğü",
    "Option c": "Simetrik anahtarların gizliliği",
    "Option d": "Quantum hesaplamanın imkansızlığı",
    "Option e": "Digital signature algoritmalarının karmaşıklığı",
    "Answer": "a"
  },
  {
    "Question": "Diffie-Hellman anahtar değişimin temel amacı nedir?",
    "Option a": "Veriyi şifrelemek",
    "Option b": "Digital signature oluşturmak",
    "Option c": "Güvenli kanal üzerinden anahtar paylaşmak",
    "Option d": "Hash değeri hesaplamak",
    "Option e": "Sertifika doğrulamak",
    "Answer": "c"
  },
  {
    "Question": "SHA-256 hash fonksiyonunun çıktı boyutu kaçtır?",
    "Option a": "128 bit",
    "Option b": "160 bit",
    "Option c": "256 bit",
    "Option d": "512 bit",
    "Option e": "1024 bit",
    "Answer": "c"
  },
  {
    "Question": "Public Key Infrastructure (PKI) sisteminde sertifikaları kim imzalar?",
    "Option a": "Son kullanıcı",
    "Option b": "Certificate Authority (CA)",
    "Option c": "Web sunucusu",
    "Option d": "DNS sunucusu",
    "Option e": "Proxy server",
    "Answer": "b"
  },
  {
    "Question": "Wireshark aracının temel işlevi nedir?",
    "Option a": "Ağ trafiğini yakalamak ve analiz etmek",
    "Option b": "Sistem güncellemelerini yapmak",
    "Option c": "Dosyaları şifrelemek",
    "Option d": "Parolaları hashlemek",
    "Option e": "Sistem performansını ölçmek",
    "Answer": "a"
  },
  {
    "Question": "Tcpdump aracında hangi parametre belirli bir porta gelen trafiği filtrelemek için kullanılır?",
    "Option a": "-i interface",
    "Option b": "-n (no name resolution)",
    "Option c": "-c count",
    "Option d": "port [port_number]",
    "Option e": "-w write",
    "Answer": "d"
  },
  {
    "Question": "Wireshark'ta display filter olarak hangi ifade HTTP trafiğini gösterir?",
    "Option a": "tcp.port == 80",
    "Option b": "http",
    "Option c": "ip.proto == 6",
    "Option d": "tcp && port 80",
    "Option e": "http.request",
    "Answer": "b"
  },
  {
    "Question": "Promiscuous mode ne anlama gelir?",
    "Option a": "Sadece kendi trafiğini dinlemek",
    "Option b": "Tüm ağ trafiğini dinlemek",
    "Option c": "Sadece hatalı paketleri yakalamak",
    "Option d": "Sadece encrypted trafiği yakalamak",
    "Option e": "Sadece broadcast paketlerini dinlemek",
    "Answer": "b"
  },
  {
    "Question": "Tcpdump ile yakalanan trafiği dosyaya kaydetmek için hangi parametre kullanılır?",
    "Option a": "-r filename",
    "Option b": "-w filename",
    "Option c": "-o filename",
    "Option d": "-s filename",
    "Option e": "-f filename",
    "Answer": "b"
  },
  {
    "Question": "Simetrik şifrelemenin temel özelliği nedir?",
    "Option a": "Şifreleme ve çözme için farklı anahtarlar kullanır",
    "Option b": "Şifreleme ve çözme için aynı anahtar kullanır",
    "Option c": "Anahtar gerektirmez",
    "Option d": "Sadece hash fonksiyonu kullanır",
    "Option e": "Sadece digital signature için kullanılır",
    "Answer": "b"
  },
  {
    "Question": "DES (Data Encryption Standard) kaç bitlik anahtar kullanır?",
    "Option a": "128 bit",
    "Option b": "256 bit",
    "Option c": "56 bit",
    "Option d": "64 bit",
    "Option e": "32 bit",
    "Answer": "c"
  },
  {
    "Question": "Simetrik şifrelemenin ana dezavantajı nedir?",
    "Option a": "Yavaş çalışması",
    "Option b": "Anahtar dağıtımı problemi",
    "Option c": "Yüksek CPU kullanımı",
    "Option d": "Sadece küçük dosyalarla çalışması",
    "Option e": "Geri dönüşü olmayan şifreleme",
    "Answer": "b"
  },
  {
    "Question": "AES (Advanced Encryption Standard) hangi anahtar boyutlarını destekler?",
    "Option a": "Sadece 128 bit",
    "Option b": "128, 192, 256 bit",
    "Option c": "Sadece 256 bit",
    "Option d": "64, 128 bit",
    "Option e": "512, 1024 bit",
    "Answer": "b"
  },
  {
    "Question": "Blowfish şifreleme algoritmasının maksimum anahtar boyutu kaçtır?",
    "Option a": "128 bit",
    "Option b": "256 bit",
    "Option c": "448 bit",
    "Option d": "512 bit",
    "Option e": "1024 bit",
    "Answer": "c"
  },
  {
    "Question": "Windows Event Log'larını temizlemek için hangi komut kullanılır?",
    "Option a": "del eventlog",
    "Option b": "wevtutil cl",
    "Option c": "clear-log",
    "Option d": "remove-event",
    "Option e": "clean-logs",
    "Answer": "b"
  },
  {
    "Question": "Sızma testi raporunda bulunması gereken temel bileşenler nelerdir?",
    "Option a": "Sadece bulunan zafiyetler",
    "Option b": "Sadece kullanılan araçlar",
    "Option c": "Uygulama özeti, metodoloji, bulgular, öneriler",
    "Option d": "Sadece risk değerlendirmesi",
    "Option e": "Sadece teknik detaylar",
    "Answer": "c"
  },
  {
    "Question": "CVSS (Common Vulnerability Scoring System) skorlaması neyi ölçer?",
    "Option a": "Sistem performansını",
    "Option b": "Zafiyet ciddiyetini",
    "Option c": "Ağ hızını",
    "Option d": "Kullanıcı memnuniyetini",
    "Option e": "Maliyet analizi",
    "Answer": "b"
  },
  {
    "Question": "Log analizi sırasında hangi bilgiler aranmalıdır?",
    "Option a": "Başarısız giriş denemeleri",
    "Option b": "Sistem değişiklikleri",
    "Option c": "Unusual network activity",
    "Option d": "Dosya erişimleri",
    "Option e": "Hepsi",
    "Answer": "e"
  },
  {
    "Question": "Remediation (düzeltme) önerilerinin öncelik sırası hangi kritere göre belirlenir?",
    "Option a": "Düzeltme maliyeti",
    "Option b": "Risk seviyesi ve iş kritikliği",
    "Option c": "Teknik zorluk",
    "Option d": "Zaman kısıtı",
    "Option e": "Personel sayısı",
    "Answer": "b"
  },
  {
    "Question": "DDoS saldırısının DoS saldırısından temel farkı nedir?",
    "Option a": "Daha güçlü araçlar kullanması",
    "Option b": "Çoklu kaynaklardan eşzamanlı saldırı",
    "Option c": "Farklı protokoller kullanması",
    "Option d": "Daha uzun sürmesi",
    "Option e": "Daha karmaşık teknikleri",
    "Answer": "b"
  },
  {
    "Question": "Botnet nedir?",
    "Option a": "Güvenlik yazılımı",
    "Option b": "Kötü amaçlı yazılımla kontrol edilen bilgisayar ağı",
    "Option c": "Ağ izleme aracı",
    "Option d": "Firewall sistemi",
    "Option e": "Antivirus programı",
    "Answer": "b"
  },
  {
    "Question": "DDoS saldırılarından korunmak için hangi yöntem en etkilidir?",
    "Option a": "Güçlü parolalar",
    "Option b": "Düzenli yedek alma",
    "Option c": "CDN ve DDoS mitigation servisleri",
    "Option d": "Antivirüs yazılımı",
    "Option e": "Sistem güncellemeleri",
    "Answer": "c"
  },
  {
    "Question": "Reflection/Amplification DDoS saldırısının çalışma prensibi nedir?",
    "Option a": "Hedefin kaynaklarını doğrudan tüketme",
    "Option b": "Üçüncü taraf sunucuları kullanarak trafiği büyütme",
    "Option c": "Ağ protokollerini bozma",
    "Option d": "Sisitem dosyalarını silme",
    "Option e": "Kullanıcı hesaplarını kilitleme",
    "Answer": "b"
  },
  {
    "Question": "Rate limiting nedir?",
    "Option a": "Dosya boyut sınırlaması",
    "Option b": "Belirli bir kaynaktan gelen istek sayısını sınırlama",
    "Option c": "Kullanıcı sayısını sınırlama",
    "Option d": "Bant genişliği sınırlaması",
    "Option e": "Zaman sınırlaması",
    "Answer": "b"
  },
  {
    "Question": "Brute force saldırısından korunmak için hangi yöntem en etkilidir?",
    "Option a": "Parola karmaşıklığını artırmak",
    "Option b": "Account lockout policy uygulamak",
    "Option c": "Multi-factor authentication",
    "Option d": "Parola geçmişi tutmak",
    "Option e": "Hepsi",
    "Answer": "e"
  },
  {
    "Question": "Dictionary attack nedir?",
    "Option a": "Kelime anlamlarını değiştirme",
    "Option b": "Yaygın parola listelerini deneme",
    "Option c": "Sözlük dosyalarını şifreleme",
    "Option d": "Dil çevirisi yapma",
    "Option e": "Kelime oyunları oynama",
    "Answer": "b"
  },
  {
    "Question": "OSINT (Open Source Intelligence) toplamanın temel amacı nedir?",
    "Option a": "Açık kaynak yazılım geliştirmek",
    "Option b": "Halka açık kaynaklardan bilgi toplamak",
    "Option c": "Sosyal medya hesabı açmak",
    "Option d": "Blog yazısı yazmak",
    "Option e": "Online eğitim almak",
    "Answer": "b"
  },
  {
    "Question": "Rainbow table saldırısında ne kullanılır?",
    "Option a": "Önceden hesaplanmış hash tabloları",
    "Option b": "Renkli grafikler",
    "Option c": "Hava durumu verileri",
    "Option d": "Müzik dosyaları",
    "Option e": "Resim albümleri",
    "Answer": "a"
  },
  {
    "Question": "Keylogger'ın temel işlevi nedir?",
    "Option a": "Klavye temizleme",
    "Option b": "Klavye tuşlarını kaydetme",
    "Option c": "Klavye hızını ölçme",
    "Option d": "Klavye ışığını ayarlama",
    "Option e": "Klavye sesini açma",
    "Answer": "b"
  },
  {
    "Question": "SQL Injection saldırısının temel prensibi nedir?",
    "Option a": "Veritabanı şifrelerini kırma",
    "Option b": "SQL sorgularına kötü amaçlı kod enjekte etme",
    "Option c": "Veritabanı dosyalarını silme",
    "Option d": "Ağ trafiğini dinleme",
    "Option e": "Sistem loglarını temizleme",
    "Answer": "b"
  },
  {
    "Question": "Union-based SQL Injection saldırısinda hangi SQL komutu kullanılır?",
    "Option a": "SELECT",
    "Option b": "INSERT",
    "Option c": "UNION",
    "Option d": "DELETE",
    "Option e": "CREATE",
    "Answer": "c"
  },
  {
    "Question": "Blind SQL Injection'da saldırgan nasıl bilgi elde eder?",
    "Option a": "Doğrudan veritabanı çıktısından",
    "Option b": "Hata mesajlarından",
    "Option c": "Uygulamanın davranış farklılıklarından",
    "Option d": "Log dosyalarından",
    "Option e": "Sistem bilgilerinden",
    "Answer": "c"
  },
  {
    "Question": "SQL Injection saldırılarından korunmanın en etkili yolu nedir?",
    "Option a": "Güçlü parolalar",
    "Option b": "Prepared statements/parameterized queries",
    "Option c": "Firewall kullanımı",
    "Option d": "Sistem güncellemeleri",
    "Option e": "Antivirus yazılımı",
    "Answer": "b"
  },
  {
    "Question": "SQLmap aracının temel işlevi nedir?",
    "Option a": "Veritabanı yedekleme",
    "Option b": "SQL Injection zafiyet tespiti ve sömürme",
    "Option c": "Veritabanı performans analizi",
    "Option d": "SQL sorgu optimizasyonu",
    "Option e": "Veritabanı şifreleme",
    "Answer": "b"
  },
  {
    "Question": "OWASP Top 10 listesinde sürekli olarak üst sıralarda yer alan web uygulama güvenlik zafiyeti hangisidir?",
    "Option a": "Distributed Denial of Service (DDoS)",
    "Option b": "Broken Access Control",
    "Option c": "Man-in-the-Middle Attack",
    "Option d": "ARP Spoofing",
    "Option e": "MAC Flooding",
    "Answer": "b"
  },
  {
    "Question": "URL yönlendirme zafiyeti (URL Redirection Vulnerability) için aşağıdaki açıklamalardan hangisi doğrudur?",
    "Option a": "Web sunucusunun yanlış yapılandırılması nedeniyle ortaya çıkan bir zafiyettir",
    "Option b": "Kullanıcının tarayıcısında JavaScript kodlarının çalıştırılmasına izin veren bir zafiyettir",
    "Option c": "Kullanıcının, güvenilir bir web sitesi üzerinden zararlı bir web sitesine yönlendirilmesine neden olan bir zafiyettir",
    "Option d": "Bir web uygulamasının veritabanından bilgi sızdırılmasına yol açan bir zafiyettir",
    "Option e": "Kullanıcının kimlik bilgilerinin web tarayıcısında saklanmasına neden olan bir zafiyettir",
    "Answer": "c"
  },
  {
    "Question": "HTML Injection zafiyeti ile ilgili aşağıdaki ifadelerden hangisi yanlıştır?",
    "Option a": "Kullanıcı girdileri doğru şekilde filtrelenmediğinde ortaya çıkabilir",
    "Option b": "Sitede görüntülenen içeriği değiştirmek için kullanılabilir",
    "Option c": "Cross-Site Scripting (XSS) saldırılarının bir türüdür",
    "Option d": "Yalnızca HTML etiketlerinin eklenmesine izin verir, JavaScript kodu çalıştırılamaz",
    "Option e": "Sayfanın görünümünü ve içeriğini değiştirerek kullanıcıları kandırmak için kullanılabilir",
    "Answer": "d"
  },
  {
    "Question": "Web uygulamalarında SQL Injection saldırısına karşı en etkili koruma yöntemi hangisidir?",
    "Option a": "Web Application Firewall (WAF) kullanmak",
    "Option b": "HTTPS protokolünü kullanmak",
    "Option c": "Parametreli sorgular (Prepared Statements) kullanmak",
    "Option d": "Captcha doğrulaması eklemek",
    "Option e": "Kullanıcı oturum süresini kısaltmak",
    "Answer": "c"
  },
  {
    "Question": "Web uygulamalarında otomatize zafiyet tarama araçları ile ilgili aşağıdakilerden hangisi doğrudur?",
    "Option a": "%100 doğrulukla tüm güvenlik açıklarını tespit edebilirler",
    "Option b": "Yalnızca manuel olarak tespit edilebilen zafiyetleri bulabilirler",
    "Option c": "Yalnızca OWASP Top 10 listesindeki zafiyetleri tarayabilirler",
    "Option d": "Sadece web sunucusu seviyesindeki güvenlik açıklarını tespit edebilirler",
    "Option e": "Birçok zafiyet türünü otomatik olarak tespit edebilirler, ancak manuel doğrulama gerektirebilir",
    "Answer": "e"
  },
  {
    "Question": "Kablosuz ağlarda veri iletimi hangi yöntemle sağlanır?",
    "Option a": "Sadece fiber optik kablolar üzerinden",
    "Option b": "Elektromanyetik dalgalar aracılığıyla",
    "Option c": "Sadece bakır kablolar üzerinden",
    "Option d": "Sadece koaksiyel kablolar üzerinden",
    "Option e": "Sadece Ethernet kabloları üzerinden",
    "Answer": "b"
  },
  {
    "Question": "Aşağıdakilerden hangisi bir kablosuz ağ bağlantı çeşidi değildir?",
    "Option a": "WLAN (Wireless Local Area Network)",
    "Option b": "WPAN (Wireless Personal Area Network)",
    "Option c": "WMAN (Wireless Metropolitan Area Network)",
    "Option d": "WWAN (Wireless Wide Area Network)",
    "Option e": "WCAN (Wireless Cable Area Network)",
    "Answer": "e"
  },
  {
    "Question": "IEEE 802.11 standardının en yaygın kullanılan versiyonu hangisidir?",
    "Option a": "IEEE 802.11a",
    "Option b": "IEEE 802.11b",
    "Option c": "IEEE 802.11g",
    "Option d": "IEEE 802.11n",
    "Option e": "IEEE 802.11ac",
    "Answer": "e"
  },
  {
    "Question": "Kablosuz ağ güvenlik protokollerinden WPA2 hangi şifreleme algoritmasını kullanır?",
    "Option a": "DES",
    "Option b": "AES",
    "Option c": "MD5",
    "Option d": "RC4",
    "Option e": "SHA-1",
    "Answer": "b"
  },
  {
    "Question": "Ad-Hoc\" çalışma modu için en doğru tanım hangisidir?",
    "Option a": "Ağ cihazlarının bir erişim noktası üzerinden iletişim kurduğu mod",
    "Option b": "Kablosuz cihazların erişim noktası olmadan doğrudan birbirleriyle iletişim kurduğu mod",
    "Option c": "Kablosuz cihazların sadece kablolu ağlarla iletişim kurduğu mod",
    "Option d": "Erişim noktasının sadece internet bağlantısı sağladığı mod",
    "Option e": "Kablosuz ağın tamamen kapalı olduğu mod",
    "Answer": "b"
  },
  {
    "Question": "Windows sistemlerde UAC (User Access Control) bypass için hangi yöntem kullanılabilir?",
    "Option a": "Registry değişiklikleri",
    "Option b": "DLL hijacking",
    "Option c": "Token impersonation",
    "Option d": "Service exploitation",
    "Option e": "Hepsi",
    "Answer": "e"
  },
  {
    "Question": "Windows Local Privilege Escalation için en yaygın kullanılan zafiyet türü hangisidir?",
    "Option a": "Cross-site scripting",
    "Option b": "Unquoted service path",
    "Option c": "DNS spoofing",
    "Option d": "ARP poisoning",
    "Option e": "Session hijacking",
    "Answer": "b"
  },
  {
    "Question": "Windows Active Directory ortamında Kerberoasting saldırısının amacı nedir?",
    "Option a": "Domain controller'ı çökertmek",
    "Option b": "Servis hesaplarının hash'lerini elde etmek",
    "Option c": "LDAP bağlantısını kesmek",
    "Option d": "DNS cache'ini temizlemek",
    "Option e": "Group Policy'leri değiştirmek",
    "Answer": "b"
  },
  {
    "Question": "Mimikatz aracının temel işlevi nedir?",
    "Option a": "Port tarama",
    "Option b": "Kimlik bilgilerini bellekten çıkarma",
    "Option c": "Dosya şifreleme",
    "Option d": "Ağ trafiği analizi",
    "Option e": "Sistem güncellemesi",
    "Answer": "b"
  },
  {
    "Question": "Windows sistemlerde AlwaysInstallElevated zafiyeti ne anlama gelir?",
    "Option a": "Sistem her zaman otomatik güncellenir",
    "Option b": "MSI paketleri her zaman yüksek yetkilerle çalışır",
    "Option c": "Sistem her zaman güvenli modda başlar",
    "Option d": "Firewall her zaman aktiftir",
    "Option e": "Antivirus her zaman çalışır",
    "Answer": "b"
  },
  {
    "Question": "Sızma testi sırasında erişim elde etmenin ilk aşaması hangisidir?",
    "Option a": "Sistemde backdoor kurulumu",
    "Option b": "Hedef sistemin keşfi ve zafiyet tespiti",
    "Option c": "Yetki yükseltme işlemi",
    "Option d": "Log dosyalarının silinmesi",
    "Option e": "Lateral movement başlatma",
    "Answer": "b"
  },
  {
    "Question": "Buffer overflow saldırısının temel amacı nedir?",
    "Option a": "Ağ trafiğini izlemek",
    "Option b": "Dosya sistemini şifrelemek",
    "Option c": "Sistem belleğinde kod çalıştırarak kontrol ele geçirmek",
    "Option d": "Kullanıcı parolalarını çalmak",
    "Option e": "Sistem loglarını temizlemek",
    "Answer": "c"
  },
  {
    "Question": "SQL Injection saldırısında hangi parametre kullanılarak veritabanına erişim sağlanır?",
    "Option a": "HTTP başlıkları",
    "Option b": "Kullanıcı giriş alanları",
    "Option c": "SSL sertifikaları",
    "Option d": "DNS kayıtları",
    "Option e": "ARP tablosu",
    "Answer": "b"
  },
  {
    "Question": "Phishing saldırısının ana hedefi nedir?",
    "Option a": "Sistem kaynaklarını tüketmek",
    "Option b": "Kullanıcı kimlik bilgilerini çalmak",
    "Option c": "Ağ bağlantısını kesmek",
    "Option d": "Dosyaları şifrelemek",
    "Option e": "Sistem performansını düşürmek",
    "Answer": "b"
  },
  {
    "Question": "Reverse shell nedir?",
    "Option a": "Hedef sistemin güvenlik duvarını devre dışı bırakma",
    "Option b": "Uzak sistemden saldırganın makinesine bağlantı kurma",
    "Option c": "Dosya sistemini tersine çevirme",
    "Option d": "Şifreli bağlantıyı çözme",
    "Option e": "Sistem saatini geri alma",
    "Answer": "b"
  },
  {
    "Question": "Kablosuz ağlarda keşif yapma yöntemlerinden hangisi pasif keşif olarak değerlendirilir?",
    "Option a": "Probe Request paketleri göndermek",
    "Option b": "Deauthentication paketleri göndermek",
    "Option c": "Beacon Frame'leri dinlemek",
    "Option d": "ARP paketleri göndermek",
    "Option e": "Ping taraması yapmak",
    "Answer": "c"
  },
  {
    "Question": "Kablosuz Ağ Saldırı Tespit Sistemleri (WIDS) hakkında aşağıdakilerden hangisi yanlıştır?",
    "Option a": "Yetkisiz erişim noktalarını tespit edebilir",
    "Option b": "MAC spoofing saldırılarını tespit edebilir",
    "Option c": "Deauthentication saldırılarını tespit edebilir",
    "Option d": "Tüm saldırı türlerini %100 doğrulukla tespit edebilir",
    "Option e": "Ağ trafiğini analiz ederek anormal davranışları belirleyebilir",
    "Answer": "d"
  },
  {
    "Question": "Aşağıdakilerden hangisi kablosuz ağlarda rogue (sahte) erişim noktalarının tespiti için kullanılan bir yöntem değildir?",
    "Option a": "RF fingerprinting analizi",
    "Option b": "Zaman tabanlı analiz",
    "Option c": "Trafik analizi",
    "Option d": "IP adresi bloklama",
    "Option e": "MAC adresi karşılaştırması",
    "Answer": "d"
  },
  {
    "Question": "Kablosuz ağlarda aktif ve pasif parmak izi toplama (fingerprinting) yöntemleri arasındaki fark nedir?",
    "Option a": "Aktif yöntemler daha hızlıdır, pasif yöntemler daha yavaştır",
    "Option b": "Aktif yöntemler sadece yöneticiler tarafından kullanılabilir, pasif yöntemler herkes tarafından kullanılabilir",
    "Option c": "Aktif yöntemler ağa paket göndererek bilgi toplar, pasif yöntemler sadece dinleme yaparak bilgi toplar",
    "Option d": "Aktif yöntemler sadece erişim noktalarını tespit eder, pasif yöntemler tüm cihazları tespit eder",
    "Option e": "Aktif yöntemler WPA/WPA2 ağlarında, pasif yöntemler sadece WEP ağlarında çalışır",
    "Answer": "c"
  },
  {
    "Question": "Kablosuz ağ saldırı tespit sistemlerinde \"Anomali Tabanlı Tespit\" yöntemi neye dayanır?",
    "Option a": "Bilinen saldırı imzalarının veritabanına",
    "Option b": "Normal ağ trafiği modelinden sapmaların tespitine",
    "Option c": "Güvenlik duvarı kurallarına",
    "Option d": "Sadece kullanıcı davranışlarının izlenmesine",
    "Option e": "Yalnızca protokol analizine",
    "Answer": "b"
  },
  {
    "Question": "Web Uygulama Güvenlik Duvarı (WAF) ile ilgili aşağıdakilerden hangisi yanlıştır?",
    "Option a": "HTTP trafiğini izler ve analiz eder",
    "Option b": "SQL Injection ve XSS gibi saldırıları engelleyebilir",
    "Option c": "Doğrudan veritabanı güvenliğini sağlar ve veritabanı üzerindeki tüm saldırıları engeller",
    "Option d": "İmza tabanlı ve davranışsal analiz yöntemlerini kullanabilir",
    "Option e": "Hem donanım hem de yazılım tabanlı çözümleri mevcuttur",
    "Answer": "c"
  },
  {
    "Question": "Web servislerinin keşfedilmesi için kullanılan yöntemlerden hangisi değildir?",
    "Option a": "WSDL dosyalarının incelenmesi",
    "Option b": "DNS zone transfer saldırıları",
    "Option c": "Dizin tarama araçları kullanma",
    "Option d": "API dokümantasyonlarını inceleme",
    "Option e": "TCP/IP paket analizi yapma",
    "Answer": "e"
  },
  {
    "Question": "Web uygulama güvenlik duvarlarını (WAF) atlatma teknikleri arasında hangisi yer almaz?",
    "Option a": "HTTP parametre kirliliği (HTTP Parameter Pollution)",
    "Option b": "Kodlama varyasyonları (Encoding Variations)",
    "Option c": "SSL/TLS kullanımı",
    "Option d": "Bölünmüş saldırılar (Fragmented Attacks)",
    "Option e": "HTTP Yöntem değiştirme (HTTP Method Tampering)",
    "Answer": "c"
  },
  {
    "Question": "Web servislerine yönelik zafiyetlerden \"XML External Entity (XXE)\" saldırısı neyi hedefler?",
    "Option a": "Servis kodlarının çalınmasını",
    "Option b": "Sunucu dosya sistemine erişimi",
    "Option c": "Sadece veritabanı bağlantılarını kesmeyi",
    "Option d": "Sadece hizmet reddi (DoS) saldırısı gerçekleştirmeyi",
    "Option e": "Sadece oturum bilgilerini çalmayı",
    "Answer": "b"
  },
  {
    "Question": "Web servislerinde REST API güvenliği için aşağıdakilerden hangisi en az önemlidir?",
    "Option a": "API anahtarları ve token tabanlı kimlik doğrulama",
    "Option b": "HTTPS protokolü kullanımı",
    "Option c": "İstek sınırlama (Rate Limiting)",
    "Option d": "CORS (Cross-Origin Resource Sharing) yapılandırması",
    "Option e": "API endpoint'lerin gizli ve tahmin edilemez URL'lere sahip olması",
    "Answer": "e"
  },
  {
    "Question": "Lateral movement'ın temel amacı nedir?",
    "Option a": "Sistem performansını artırmak",
    "Option b": "Ağ içinde başka sistemlere erişim sağlamak",
    "Option c": "Dosyaları yedeklemek",
    "Option d": "Güvenlik güncellemelerini yapmak",
    "Option e": "Ağ bant genişliğini artırmak",
    "Answer": "b"
  },
  {
    "Question": "Pass-the-Hash saldırısında ne kullanılır?",
    "Option a": "Şifreli parolalar",
    "Option b": "Hash değerleri",
    "Option c": "SSL sertifikaları",
    "Option d": "MAC adresleri",
    "Option e": "IP adresleri",
    "Answer": "b"
  },
  {
    "Question": "SMB protokolü üzerinden yapılan lateral movement için hangi araç yaygın kullanılır?",
    "Option a": "Nmap",
    "Option b": "PsExec",
    "Option c": "Wireshark",
    "Option d": "Burp Suite",
    "Option e": "Metasploit Framework",
    "Answer": "b"
  },
  {
    "Question": "Windows ortamında WMI (Windows Management Instrumentation) lateral movement için nasıl kullanılır?",
    "Option a": "Dosya transferi için",
    "Option b": "Uzak komut çalıştırma için",
    "Option c": "Ağ dinleme için",
    "Option d": "Şifre çözme için",
    "Option e": "Sistem tarama için",
    "Answer": "b"
  },
  {
    "Question": "Golden Ticket saldırısı hangi protokolü hedefler?",
    "Option a": "HTTP",
    "Option b": "FTP",
    "Option c": "Kerberos",
    "Option d": "SSH",
    "Option e": "SMTP",
    "Answer": "c"
  },
  {
    "Question": "HULK (HTTP Unbearable Load King) aracının çalışma prensibi nedir?",
    "Option a": "Database kaynaklarını tüketme",
    "Option b": "Benzersiz HTTP istekleri oluşturarak cache bypass",
    "Option c": "Ağ bağlantılarını kesme",
    "Option d": "Sistem belleğini doldurma",
    "Option e": "CPU döngülerini tüketme",
    "Answer": "b"
  },
  {
    "Question": "OWASP SwitchBlade aracının temel amacı nedir?",
    "Option a": "Güvenlik zafiyet taraması",
    "Option b": "Switch ağlarında DoS saldırısı",
    "Option c": "Web uygulaması testing",
    "Option d": "Sızma testi otomasyonu",
    "Option e": "Kod analizi",
    "Answer": "b"
  },
  {
    "Question": "Time-based Blind SQL Injection'da hangi teknik kullanılır?",
    "Option a": "Error messages analizi",
    "Option b": "Database response delay",
    "Option c": "Direct output reading",
    "Option d": "HTTP status codes",
    "Option e": "Cookie manipulation",
    "Answer": "b"
  },
  {
    "Question": "CSRF (Cross-Site Request Forgery) saldırısının hedefi nedir?",
    "Option a": "Kullanıcı parolasını çalma",
    "Option b": "Kullanıcı adına isteksiz işlemler yaptırma",
    "Option c": "Web sitesini çökertme",
    "Option d": "Database'e erişim sağlama",
    "Option e": "Session token'ları çalma",
    "Answer": "b"
  },
  {
    "Question": "Slowloris saldırısının çalışma prensibi nedir?",
    "Option a": "Büyük dosyalar upload etme",
    "Option b": "Yarım HTTP bağlantılarını uzun süre açık tutma",
    "Option c": "SQL injection gerçekleştirme",
    "Option d": "Cross-site scripting",
    "Option e": "Buffer overflow",
    "Answer": "b"
  }






];

const questions = rawQuestions.map(item => ({
  question: item.Question,
  options: {
    a: item["Option a"],
    b: item["Option b"],
    c: item["Option c"],
    d: item["Option d"],
    e: item["Option e"]
  },
  answer: item.Answer
}));


function shuffle(array) {
  let currentIndex = array.length, randomIndex;

  while (currentIndex != 0) {
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    // Yer değiştir
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
  return array;
}

let selectedQuestions = shuffle([...questions]).slice(0, 20); // 20 tane rastgele seç

let currentQuestionIndex = 0;
let userAnswers = [];

// HTML elemanlarını seçelim
const quizContainer = document.getElementById("quiz");
const nextBtn = document.getElementById("next");
const resultContainer = document.getElementById("result");

// İlk soruyu göster
function showQuestion() {
  const q = selectedQuestions[currentQuestionIndex];
  let optionsHTML = "";
  for (const [key, text] of Object.entries(q.options)) {
    optionsHTML += `
      <label>
        <input type="radio" name="answer" value="${key}" />
        ${key}) ${text}
      </label><br/>
    `;
  }
  quizContainer.innerHTML = `
    <div>
      <h3>Soru ${currentQuestionIndex + 1} / 20</h3>
      <p>${q.question}</p>
      <form id="quiz-form">${optionsHTML}</form>
    </div>
  `;

  // Next butonuna basılana kadar result gizli olsun
  resultContainer.innerHTML = "";
}

showQuestion();

// Sonraki soruya geç
nextBtn.addEventListener("click", () => {
  const selectedOption = document.querySelector('input[name="answer"]:checked');
  if (!selectedOption) {
    alert("Lütfen bir şık seçin.");
    return;
  }
  userAnswers[currentQuestionIndex] = selectedOption.value;

  currentQuestionIndex++;

  if (currentQuestionIndex < selectedQuestions.length) {
    showQuestion();
  } else {
    showResult();
  }
});

// Sonuçları göster
function showResult() {
  let correctCount = 0;
  let resultHTML = "<h2>Sonuçlar</h2>";

  selectedQuestions.forEach((q, i) => {
    const userAnswer = userAnswers[i];
    const isCorrect = userAnswer === q.answer;
    if (isCorrect) correctCount++;

    resultHTML += `
      <div style="margin-bottom: 15px;">
        <strong>Soru ${i + 1}:</strong> ${q.question}<br/>
        <span style="color: ${isCorrect ? "green" : "red"}">
          Senin cevabın: ${userAnswer}) ${q.options[userAnswer]}
        </span><br/>
        ${!isCorrect ? `<span style="color: blue;">Doğru cevap: ${q.answer}) ${q.options[q.answer]}</span>` : ""}
      </div>
    `;
  });

  resultHTML += `<h3>Doğru sayısı: ${correctCount} / 20</h3>`;
  quizContainer.innerHTML = "";
  resultContainer.innerHTML = resultHTML;
}

});