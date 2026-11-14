# Windows sanal makinesinde doğrulama

Bu adımlar gerçek ağ ve dosya ayarlarını etkileyebilir. Yalnızca size ait, yedeklenmiş ve kontrol noktası alınmış bir Windows 10/11 sanal makinesinde uygulayın. Test sonunda sanal makineyi kontrol noktasına geri döndürün. Fiziksel cihazlarda veya önemli verilerde bu adımları uygulamayın.

## Hazırlık

1. `install.bat` ile bağımlılıkları kurun ve otomatik testleri çalıştırın: `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.
2. Windows sürümünü, Python sürümünü, yönetici yetkisini ve kullanılan ağ bağdaştırıcısını kaydedin. Test ağı için ayrı bir sanal bağdaştırıcı tercih edin.
3. Windows ağ ayarlarında seçili bağdaştırıcının IPv4 DNS modunu (otomatik veya elle) ve adreslerini kaydedin. `Get-DnsClientServerAddress -AddressFamily IPv4` mevcut adresleri gösterebilir; tek başına modun doğrulaması değildir.
4. Sanal makine sağlayıcısında kontrol noktası alın. Komut veya arayüzde hata görünürse durun, sonucu kaydedin ve kontrol noktasına dönün.

## DNS değişikliği ve geri alma

1. Yönetici terminalinde `dns_switcher.py` açın. Önceki modu boş bırakıp işlemi iptal edin; Windows ayarlarının değişmediğini kontrol edin.
2. Önceki gerçek modu ve bağdaştırıcıyı doğru seçerek bir test DNS profili uygulayın. İşlem bitince Windows ağ ayarlarında hem IPv4 adreslerini hem modu kontrol edin. DNS çözümlemesini ayrı bir test sorgusuyla doğrulayın.
3. Önceki ayarı Windows ağ arayüzünden geri yükleyin; adresleri ve modu yeniden kontrol edin. Otomatik geri alma hata durumunda çalışır; gerçek geri alma davranışı ayrıca yalnızca kontrollü hata üretebilen bir laboratuvarda sınanmalıdır. Ağ kesintisi veya zorla sonlandırma kullanmayın.
4. IPv6 DNS, VPN ve kuruluş ilkeleri ayrıca incelenmelidir; aracın bunları geri yüklediği varsayılmamalıdır.

## Hosts ve dosya kontrolleri

1. Hosts testinden önce özgün hosts içeriğini güvenli bir konuma alın. Aracı yalnızca yönetici test terminalinde kullanın; kişisel bir hosts kaydının etkinleştirme ve kaldırma sonrasında korunduğunu kontrol edin. Ardından VM kontrol noktasına dönün.
2. ShredIt için yalnızca test amacıyla oluşturulmuş ve kaybı önemsiz bir dosya kullanın. Bağlantılar, junction ve hard link davranışını gerçek kullanıcı dosyaları olmadan test edin. SSD ve yedeklerde geri getirilemezlik iddiasını bu testle doğrulayamazsınız.
3. DNS Sinkhole varsayılan `5353` portunda yerel TCP/UDP sorgularıyla denenebilir; sistem DNS ayarları değiştirilmeden `nslookup -port=5353 ads.google.com 127.0.0.1` kullanın.

## Sonuç kaydı

Geçen ve başarısız adımları, hata mesajlarını ve geri alma sonucunu not edin. Kasa, parola, DNS geçmişi veya diğer hassas raporları herkese açık issue ya da repoya yüklemeyin. Bu belge manuel doğrulama planıdır; gerçek ortamda başarıyla çalıştırıldığı anlamına gelmez.
