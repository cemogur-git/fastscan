# fastscan

Yüksek performanslı, cloud-native TCP port scanner.
Go ile yazılmış; raw socket SYN scan, banner grabbing ve JSON pipeline çıktısı destekler.

## ⚠️ Yasal Uyarı

Sahip olduğunuz veya yazılı izin aldığınız sistemlerde kullanın.
Tüm sorumluluk kullanıcıya aittir.

## Özellikler

- TCP Connect Scan ve SYN Stealth Scan
- CIDR, range ve tekil IP desteği
- Banner grabbing ve servis tespiti
- JSON, CSV ve table çıktı formatları
- Bubbletea TUI ile canlı ilerleme
- Cloud-native: JSON çıktı ile pipeline entegrasyonu

## Kurulum

### Gereksinimler

- Go 1.22+
- libpcap-dev (SYN scan için)
- Linux (AF\_PACKET desteği)

### Derleme

```bash
git clone https://github.com/KULLANICI/fastscan
cd fastscan
make build
```

## Kullanım

```bash
# Connect scan (sudo gerekmez)
./fastscan --target 192.168.1.0/24 --ports 1-1024

# SYN stealth scan (sudo gerekir)
sudo ./fastscan --target 192.168.1.1 \
                --ports 1-65535 \
                --stealth \
                --concurrency 5000

# JSON çıktı
./fastscan --target 10.0.0.1 --output json

# Dosyaya kaydet
./fastscan --target 10.0.0.1 --output csv --outfile results.csv
```

## Mimari

Her katman yalnızca kendi sorumluluğunu taşır; paketler arası döngüsel bağımlılık yoktur.

```
fastscan/
├── cmd/scanner/     # CLI giriş noktası (cobra) + Bubbletea TUI
├── pkg/network/     # Raw socket, SYN paket inşası (CAP_NET_RAW)
├── pkg/scan/        # Connect scan, aggregator, export (JSON/CSV)
├── pkg/utils/       # CIDR/range/port parser, structured logging
└── tests/           # Entegrasyon testleri (loopback + mock socket)
```

Tarama akışı:

```
ParseTargets  ──►  ParsePorts  ──►  Scanner.Scan
                                        │
                                   Aggregator.Collect
                                        │
                              ExportJSON / ExportCSV / table
```

## Katkı

Standart fork + PR akışı:

1. Repo'yu fork edin
2. Feature branch açın: `git checkout -b feat/yeni-ozellik`
3. `make test` ve `make lint` sıfır hata geçmeli
4. PR açın
