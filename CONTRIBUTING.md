# Katkıda bulunma

Katkılarınızı kendi yetkili test ortamınızda hazırlayın. Değişikliğin ne yaptığını, hangi sürümde denendiğini ve ilgili testleri açıklayın. Güvenlik açığı ayrıntılarını herkese açık issue yerine SECURITY.md içindeki özel bildirim yoluyla paylaşın.

Windows üzerinde Python 3.10–3.12 ve proje bağımlılıklarıyla testleri çalıştırın:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Testler gerçek hosts, DNS veya sistem ayarlarını değiştirmemelidir. Bu işlemleri elle doğrulamak için yedeği olan izole bir Windows sanal makinesi kullanın; denenen Windows sürümünü, izinleri ve geri alma sonucunu belirtin. Parolaları, tokenları, raporları, adli veri paketlerini ve gerçek kullanıcı verilerini repoya eklemeyin. Çıktıları paylaşmadan önce gizli verileri gözden geçirin.

Yeni özellikler için yapılan kontrolün sınırlarını ve eksik yetki veya komut hatalarında ne olacağını kullanıcıya açıkça gösterin. Gerektiğinde anlamlı regresyon testleri ekleyin. Üçüncü taraf yazılımın lisans ve dağıtım koşullarına uyun.
