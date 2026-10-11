# SubSeven – Subdomain Tarayıcı

Sertifika şeffaflığı (Certificate Transparency) kayıtları ve DNS çözümlemesi ile bir alan adının alt alan adlarını (subdomain) keşfeden, isteğe bağlı olarak bulunan hostların HTTP(S) yanıtlarını kontrol eden hafif bir Python aracıdır.

> ⚠️ **Yasal uyarı:** Bu aracı yalnızca sahibi olduğunuz veya test etme yetkinizin bulunduğu alan adlarında kullanın. İzinsiz tarama yasa dışı olabilir. Sorumluluk kullanıcıya aittir.

## Özellikler

- **Pasif keşif:** [crt.sh](https://crt.sh) üzerinden sertifika şeffaflığı kayıtlarını sorgular.
- **Aktif keşif:** Yerleşik kelime listesi (~200 yaygın önek: `www`, `api`, `admin`, `vpn`, `staging` vb.) ve isteğe bağlı özel kelime listesi ile DNS çözümlemesi dener.
- **Eşzamanlı çalışma:** DNS ve HTTP kontrolleri thread havuzu ile paralel yürütülür.
- **HTTP(S) kontrolü:** Çözümlenen her host için `https` ve `http` isteği atar; durum kodunu, `Server` başlığını ve sayfa başlığını (`<title>`) toplar. Yalnızca ilk 8 KB okunur.
- **Çoklu çıktı formatı:** Sonuçları JSON, CSV veya düz metin olarak kaydedebilir.
- **Harici bağımlılık yok:** Yalnızca Python standart kütüphanesini kullanır.
- **Güvenli girdi doğrulama:** IDNA/Unicode alan adlarını destekler, geçersiz alan adlarını ve IP adreslerini reddeder.

## Gereksinimler

- Python **3.8** veya üzeri
- İnternet erişimi (crt.sh sorgusu ve DNS/HTTP kontrolleri için)

## Kurulum

```bash
git clone https://github.com/f3nr1rs3c/Subseven.git
cd Subseven
python3 subseven.py --help
```

## Kullanım

```bash
python3 subseven.py example.com
```

Alan adı konumsal argüman veya `-d` ile verilebilir:

```bash
python3 subseven.py -d example.com
```

### Parametreler

| Parametre | Açıklama | Varsayılan |
|---|---|---|
| `domain` / `-d`, `--domain` | Kök alan adı (ör. `example.com`) | – |
| `-w`, `--wordlist` | Ek kelime listesi dosyası (satır başına bir isim, `#` ile yorum) | – |
| `--passive-only` | Yerleşik ve özel kelime listesiyle DNS denemelerini atlar | kapalı |
| `--no-ct` | crt.sh sertifika şeffaflığı sorgusunu atlar | kapalı |
| `--no-http` | HTTP/HTTPS kontrollerini atlar | kapalı |
| `--timeout` | Ağ zaman aşımı (saniye, 0.5–120) | `5` |
| `--workers` | Eşzamanlı işçi sayısı (1–50) | `20` |
| `--max-candidates` | Çözümlenecek en fazla benzersiz isim (1–100000) | `5000` |
| `-o`, `--output` | Sonuçların yazılacağı dosya | – |
| `--format` | Çıktı formatı: `json`, `csv`, `txt` | `json` |
| `--user-agent` | HTTP User-Agent değeri | `SubSeven-SubdomainScanner/1.0` |

### Örnekler

Varsayılan tarama (CT + yerleşik liste + HTTP kontrolü):

```bash
python3 subseven.py example.com
```

Yalnızca pasif keşif, HTTP kontrolü olmadan:

```bash
python3 subseven.py example.com --passive-only --no-http
```

Özel kelime listesi ile tarama ve JSON raporu:

```bash
python3 subseven.py example.com -w wordlist.txt -o sonuc.json
```

Sadece hostname listesini düz metin olarak kaydetme:

```bash
python3 subseven.py example.com --format txt -o subdomainler.txt
```

Daha hızlı ve geniş tarama:

```bash
python3 subseven.py example.com --workers 50 --timeout 3 --max-candidates 20000 -w buyuk_liste.txt
```

## Örnek Çıktı

```
[*] Domain: example.com
[*] Gathering names and resolving DNS...
[*] Resolved 3 of 214 candidate names.
HOSTNAME          ADDRESSES       HTTP(S)          TITLE
----------------  --------------  ---------------  ---------------
example.com       93.184.216.34   200 https, ...   Example Domain
www.example.com   93.184.216.34   200 https, ...   Example Domain
```

## Çıktı Formatları

- **json:** Alan adı, tarama zamanı (UTC), toplam sayı ve her host için adresler, kaynaklar (`crt.sh`, `built-in`, `wordlist`, `root`) ve HTTP bilgilerini içerir.
- **csv:** `hostname, addresses, sources, http_statuses, titles` sütunlarından oluşur; çoklu değerler `;` ile ayrılır.
- **txt:** Her satırda bir hostname.

## Nasıl Çalışır?

1. Girilen alan adı doğrulanır ve normalize edilir (IDNA, küçük harf, joker karakter temizliği).
2. Aday isimler toplanır: crt.sh kayıtları, yerleşik önek listesi ve varsa özel kelime listesi.
3. Adaylar benzersizleştirilir; `--max-candidates` sınırı aşılırsa uyarı verilip ilk N isim işlenir.
4. Her aday paralel olarak DNS ile çözümlenir; yalnızca çözümlenenler sonuçlara eklenir.
5. `--no-http` verilmediyse çözümlenen hostlara `https://` ve `http://` ile istek atılır.
6. Sonuçlar tablo olarak ekrana basılır, istenirse dosyaya yazılır.

## Notlar ve Sınırlamalar

- `*.example.com` gibi joker karakterli sertifika kayıtları atlanır.
- DNS çözümlemesi sistemin varsayılan çözümleyicisini kullanır; çok sayıda sorgu ağ yöneticiniz veya DNS sağlayıcınız tarafından fark edilebilir.
- HTTPS isteklerinde sertifika doğrulaması açıktır; geçersiz sertifikalı hostlar için HTTPS sonucu görünmeyebilir.
- crt.sh bazen yavaş yanıt verebilir veya hata dönebilir. Bu durumda uyarı verilir ve tarama diğer kaynaklarla devam eder.
- Yoğun taramalarda `--workers` değerini hedef ve ağınıza zarar vermeyecek şekilde ayarlayın.

## Lisans

Lisans bilgisini buraya ekleyin (ör. MIT).
