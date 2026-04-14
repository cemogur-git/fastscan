# FASTSCAN PROJECT — CLAUDE CODE RULES

## Project Context
Go ile yazılmış yüksek performanslı, cloud-native 
TCP port scanner kütüphanesi ve CLI aracı.

Amaç: GitHub portföyü — network güvenlik araçlarına
ve Go sistem programlamaya hakimiyeti göstermek.

Kullanım: Yalnızca kullanıcının sahip olduğu veya
yazılı izin aldığı ağlarda kullanılabilir.

## Tech Stack
- Dil: Go 1.22+
- Raw socket: AF_PACKET + libpcap (google/gopacket)
- CLI: cobra
- TUI: bubbletea
- Test: go test + testify
- Lint: golangci-lint

## Klasör Yapısı
/cmd/scanner     → CLI giriş noktası (main.go)
/pkg/network     → Raw socket, paket oluşturma
/pkg/scan        → Tarama algoritmaları
/pkg/utils       → CIDR parser, port parser, logging
/tests           → Entegrasyon testleri
/docs            → Dokümantasyon

## DAIMA UYMASI GEREKEN KURALLAR

### Kod Kalitesi
- Her public fonksiyonun GoDoc yorumu olacak
- Her paketin _test.go dosyası olacak
- go vet sıfır hata geçmeli
- Error'lar wrap edilerek yukarı fırlatılacak (fmt.Errorf + %w)
- Magic number yok, sabitler const bloğunda tanımlanacak
- Context her uzun süren işleme parametre olarak geçilecek
- Goroutine leak olmayacak (defer cancel pattern zorunlu)
- Her struct için constructor fonksiyonu yazılacak (NewXxx)

### Mimari
- Interface'ler önce tanımlanacak, sonra implement edilecek
- Paketler arası döngüsel bağımlılık olmayacak
- Config struct her tarama fonksiyonuna parametre olacak
- Somut tipler interface üzerinden kullanılacak

### Git Disiplini
- Her tamamlanan modül commit edilecek
- Format: feat/fix/refactor/test: kısa açıklama
- main branch'e direkt push yapılmayacak
- Her commit derlenebilir olacak

### Güvenlik Kodu Standartları
- Raw socket işlemleri SADECE /pkg/network altında
- CAP_NET_RAW gerektiren her fonksiyon dokümante edilecek
- Timeout her network operasyonunda zorunlu
- Rate limiter varsayılan olarak aktif olacak
- Kullanıcıya yasal uyarı her zaman gösterilecek

## YASAK KURALLAR

### Kod Yasakları
- panic() kullanma → her zaman error döndür
- global state kullanma → struct field'larına taşı
- init() fonksiyonu kullanma
- os.Exit() sadece main() içinde kullanılabilir
- naked return kullanma
- interface{} / any kullanma → generic veya somut tip
- Senkron DNS lookup yapma
- Unbounded goroutine açma → her zaman pool/semaphore

### Mimari Yasakları
- /pkg/network dışında raw socket kodu yazma
- Test dosyalarında gerçek dış ağ bağlantısı kurma
- Hardcoded IP veya port yazma
- Binary içine credential gömmeme

### Dokümantasyon Yasakları
- "TODO" bırakma → ya implement et ya issue aç
- Yorum satırı "ne yaptığını" değil "neden yaptığını" açıklasın

## Bağımlılıklar (go.mod'a eklenecekler)
- github.com/google/gopacket       → raw packet işleme
- github.com/spf13/cobra           → CLI
- github.com/charmbracelet/bubbletea → TUI
- github.com/stretchr/testify      → test assertion
- golang.org/x/sync                → semaphore / errgroup

## Geliştirme Sırası
1. go.mod + bağımlılıklar
2. /pkg/utils → CIDR parser, port parser
3. /pkg/scan  → Connect scan (baseline)
4. /pkg/network → Raw socket, SYN scan
5. /cmd/scanner → CLI + TUI
6. /tests → Entegrasyon testleri
7. README + docs
