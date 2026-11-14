# WinSecX / KaliLiteX

Windows için Python tabanlı güvenlik envanteri, ağ denetimi ve yardımcı araçlar. Ana menü ile 19 bağımsız araca erişilebilir. Proje geliştirme aşamasındadır; sonuçlar tek başına güvenlik garantisi veya kapsamlı bir EDR/antivirüs yerine geçmez.

**Platform:** Windows 10/11 · **Hedef Python sürümleri:** 3.10–3.12 · **Arayüz:** terminal

Yalnızca size ait veya test etmek için açık izin aldığınız sistemlerde kullanın. DNS, hosts, sistem ayarları ve dosya silme işlemlerini önce yedeklenmiş bir test ortamında deneyin.

## Kurulum

1. Python 3.10–3.12 kurun ve Python Launcher veya `python` komutunun erişilebilir olduğunu doğrulayın.
2. `install.bat` dosyasını çalıştırın. Proje içinde `.venv` sanal ortamı oluşturulur ve bağımlılıklar yüklenir.
3. `start.bat` ile ana menüyü açın. Bazı işlemler yönetici yetkisi gerektirir; yalnızca gerekli işlemler için yükseltilmiş bir terminal kullanın.

Elle kurulum:

```powershell
$env:PYTHONUTF8 = "1"
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe kalisuite.py
```

Tek bir aracı çalıştırmak için örnek: `.\.venv\Scripts\python.exe file_integrity.py`. Nmap ve SQLMap menüden çağrılabilir; bu programlar projeye dâhil değildir ve ayrıca kurulmaları gerekir.

## Araçlar

| Dosya | Kategori | Açıklama |
|---|---|---|
| **`shredit.py`** | Dosya İmha | Dosyaları üzerine yazarak siler; SSD, yedekler ve dosya sistemlerinde geri getirilemezlik garantisi yoktur. |
| **`netguard.py`** | Ağ Radarı | Genel IP TCP bağlantılarını iki saniyede bir sorgular; UDP ve kısa bağlantılar kaçabilir. |
| **`adguard.py`** | Reklam/Casusluk | İndirilen listeyi hosts dosyasında yönetilen bir blokta kullanır; diğer kayıtları korur. |
| **`forensix.py`** | Adli Bilişim | Süreç, bağlantı, DNS önbelleği, USB kayıtları ve sistem bilgilerini toplamayı dener; ZIP içinde işlem durumunu raporlar. |
| **`passvault.py`** | Parola Kasası | Yerel, AES-GCM ve scrypt kullanan parola kasası. Kasa LOCALAPPDATA/WinSecX içinde saklanır; eski konumdaki kasa isteğe bağlı kopyalanıp dönüştürülür. |
| **`malscan.py`** | Zararlı Avcısı | Seçilmiş dosya adı ve uzantı kalıplarını listeler; zararlı olduğunu doğrulamaz veya dosyaları silmez. |
| **`cert_guard.py`** | Sertifika envanteri | Yerel makinenin kök sertifikalarını ve parmak izlerini listeler; güvenilirlik kararı vermez. |
| **`dns_switcher.py`** | DNS ayarları | Seçilen bağdaştırıcının IPv4 DNS ayarlarını değiştirir; önceki modu ve geri alma sonucunu kontrol edin. |
| **`leak_watch.py`** | Veri Sızıntısı | Dosyalardaki unutulmuş kredi kartı, şifre ve API key sızıntılarını tarar. |
| **`sys_hardening.py`** | Sistem ayarları | SMBv1, AutoPlay, LLMNR ve RDP ayarlarını değiştirmeyi dener; yetki ve bazen yeniden başlatma gerekir. |
| **`keylogger_hunter.py`** | Casus Avcısı | Süreç adlarında şüpheli kelimeleri arar; klavye kancalarını incelemez. |
| **`port_forward_checker.py`** | Dış Güvenlik | Genel IPv4 ve kullanıcının girdiği WAN IPv4 karşılaştırması; dış port testi yapmaz. |
| **`eviltwin_radar.py`** | Wi-Fi Koruması | Aynı SSID için birden fazla erişim noktasını işaretler; sahte erişim noktasını doğrulamaz. |
| **`firewall_auditor.py`** | Güvenlik Duvarı | Gelen izin kurallarını ve kural adındaki seçili kelime eşleşmelerini listeler. |
| **`shadow_user_hunter.py`** | Hesap Avcısı | Yerel hesapları ve doğrudan yönetici üyeliğini listeler; iç içe grupları çözmez. |
| **`hollow_hunter.py`** | Süreç Doğrulama | Bazı sistem süreçlerinin yollarını inceler; process hollowing veya dijital imza doğrulamaz. |
| **`file_integrity.py`** | Bütünlük Nöbeti | Seçili dosyaları eksiksiz SHA-256 referansı ile karşılaştırır; referansın temizliğini doğrulamaz. |
| **`dns_sinkhole.py`** | Ağ Kapanı | İsteğe bağlı yerel TCP/UDP DNS hizmeti; örnek veya kullanıcı listesini uygular. Sistem DNS ayarlarını değiştirmez. |
| **`byovd_auditor.py`** | Çekirdek Güvenliği | Sürücü adlarını kısa bir listeyle karşılaştırır; sürüm ve dijital imzayı doğrulamaz. |


## Testler

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Testler geçici dosyalar, taklit edilmiş Windows komutları ve yerel döngü adresindeki TCP/UDP soketlerini kullanır. Yönetici yetkisiyle gerçek DNS, hosts veya Windows güvenlik ayarlarını değiştirmez. Windows test ortamlarında gerçek ayar değişiklikleri ve geri alma ayrıca doğrulanmalıdır; bkz. [Windows doğrulama planı](docs/WINDOWS_VALIDATION.md). GitHub Actions, Windows üzerinde Python 3.10–3.12 ile testleri çalıştıracak şekilde yapılandırılmıştır; gerçek sonuçlar repo GitHub'a yüklendikten sonra Actions sekmesinde görülür.

## Güvenlik ve sınırlar

- **Tespit kapsamı:** Süreç, Wi-Fi, ARP, sürücü ve dosya adı kontrolleri sınırlı ön kontrollerdir. Eşleşme bulunmaması cihazın güvenli olduğunu kanıtlamaz. Yem dosyası ve ARP izleyicileri yalnızca program açıkken uyarı verir; saldırıyı durdurmaz.
- **DNS:** Sinkhole yalnızca kendisine yönlendirilen yerel TCP/UDP sorgularını işler. DoH/DoT, IPv6 DNS ve başka çözümleyiciler kapsam dışında; varsayılan liste üç örnek içerir. Üst DNS sorguları şifrelenmeden iletilir. DNS değiştirici hatada kullanıcının belirttiği önceki moda dönmeyi dener; modu ve sonucu Windows ayarlarında doğrulayın.
- **Dosya silme:** Üzerine yazma, SSD'lerde, dosya sistemi kopyalarında ve yedeklerde geri getirilemez silme garantisi vermez. Araç bağlantıları, reparse noktalarını ve çoklu sabit bağlantılı dosyaları reddeder; Windows'ta açık dosya paylaşımını kısıtlayıp silmeyi aynı tutamaç üzerinden işaretler. Tüm dosya sistemi ve eşzamanlılık senaryolarına karşı garanti yoktur.
- **Parola kasası:** Kasa `%LOCALAPPDATA%\WinSecX\passvault.enc` konumundadır. Eski konumdaki kasa kullanıcı onayıyla kopyalanabilir. Eski biçim dönüştürüldüğünde `.legacy.bak` zayıf eski şifrelemeyle kalır; yeni kasayı doğruladıktan sonra yedeği uygun biçimde yönetin. Yeni kasalar en az 12 karakterlik ana parola gerektirir. Aynı kasayı açan PassVault örnekleri oturum kilidi kullanır; başka uygulamalar tarafından dosyanın değiştirilmesine karşı koruma sağlamaz.
- **Bütünlük:** Referans oluşturulurken gösterilen SHA-256 değerini ayrı, güvenilir bir yerde saklayın. Sonraki kontrolde bu değer girilmezse referansın kendisi doğrulanmaz. Referansın temiz bir sistemden alındığı ayrıca doğrulanmalıdır.
- **Raporlar:** Forensix çıktıları, DNS önbelleği, kullanıcı ve ağ bilgileri içerebilir. Raporları ve kasa dosyalarını GitHub'a yüklemeyin. `.gitignore` yeni eklenen yerel çıktıları kapsamaya yardımcı olur, zaten takip edilen dosyaları kaldırmaz.
- **Eski betikler:** Klasördeki bağımsız `.ps1` ve `windows_security_batch.bat` dosyaları eski araçlardır; bu Python test paketi bunların davranışını doğrulamaz. Kullanımdan önce ayrıca incelenmelidir.
- **Bağımlı hizmetler:** Bazı seçenekler URLhaus, HIBP, crt.sh, genel IP servisi veya DNS sağlayıcısıyla iletişim kurar; sorgu sırasında bilgi ilgili hizmete gönderilir. VirusTotal ve e-posta seçenekleri otomatik sorgu yerine bağlantı oluşturur.

### Yerel DNS filtresini deneme

`.\.venv\Scripts\python.exe dns_sinkhole.py` komutunu çalıştırıp başlatmayı onaylayın. Ayrı bir terminalde `nslookup -port=5353 ads.google.com 127.0.0.1` ile örnek alan adını sorgulayın. İsteğe bağlı olarak `--port 53 --blocklist engelli.txt` kullanılabilir; dosya alan adları veya hosts biçiminde olabilir. Port 53 kullanımda ise sunucu başlamaz. Sistem ayarları otomatik değiştirilmez; sunucu durduğunda sisteme yerel DNS atanmışsa çözümleme aksayabilir.

## Lisans ve katkı

Mevcut [LICENSE.md](LICENSE.md) metni MIT benzeri izinleri **KaliLiteX çekirdek Python düzenleyicisi** için tanımlar; diğer proje dosyalarının lisans kapsamını ayrıca belirtmez. Üçüncü taraf araçlar kendi lisanslarına tabidir. Proje sahibi yayın öncesi tüm dosyalar için istenen lisans kapsamını netleştirmelidir.

Katkı ve hata bildirimi için [CONTRIBUTING.md](CONTRIBUTING.md), güvenlik açığı bildirimi için [SECURITY.md](SECURITY.md) dosyasına bakın.

Geliştirici: **ENESxAİs**
