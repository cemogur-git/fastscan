package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Well-known port numbers referenced by portServiceMap.
// Declared as typed constants to avoid magic numbers in the map literal.
const (
	portFTP           uint16 = 21
	portSSH           uint16 = 22
	portTelnet        uint16 = 23
	portSMTP          uint16 = 25
	portDNS           uint16 = 53
	portHTTP          uint16 = 80
	portPOP3          uint16 = 110
	portIMAP          uint16 = 143
	portLDAP          uint16 = 389
	portHTTPS         uint16 = 443
	portSMB           uint16 = 445
	portMSSQL         uint16 = 1433
	portOracle        uint16 = 1521
	portZooKeeper     uint16 = 2181
	portMySQL         uint16 = 3306
	portRDP           uint16 = 3389
	portPostgreSQL    uint16 = 5432
	portVNC           uint16 = 5900
	portRedis         uint16 = 6379
	portHTTPProxy     uint16 = 8080
	portHTTPSAlt      uint16 = 8443
	portKafka         uint16 = 9092
	portElasticsearch uint16 = 9200
	portMemcached     uint16 = 11211
	portMongoDB       uint16 = 27017

	// bannerReadSize is the maximum number of bytes read from a banner response.
	// 1 KiB is enough to capture all common protocol handshake strings.
	bannerReadSize = 1024
)

// portServiceMap maps well-known port numbers to human-readable service names.
// Used as a fallback by ServiceHint when no banner is available.
var portServiceMap = map[uint16]string{
	portFTP:           "FTP",
	portSSH:           "SSH",
	portTelnet:        "Telnet",
	portSMTP:          "SMTP",
	portDNS:           "DNS",
	portHTTP:          "HTTP",
	portPOP3:          "POP3",
	portIMAP:          "IMAP",
	portLDAP:          "LDAP",
	portHTTPS:         "HTTPS",
	portSMB:           "SMB",
	portMSSQL:         "MSSQL",
	portOracle:        "Oracle",
	portZooKeeper:     "ZooKeeper",
	portMySQL:         "MySQL",
	portRDP:           "RDP",
	portPostgreSQL:    "PostgreSQL",
	portVNC:           "VNC",
	portRedis:         "Redis",
	portHTTPProxy:     "HTTP-Proxy",
	portHTTPSAlt:      "HTTPS-Alt",
	portKafka:         "Kafka",
	portElasticsearch: "Elasticsearch",
	portMemcached:     "Memcached",
	portMongoDB:       "MongoDB",
}

// bannerHints maps upper-cased banner substrings to service names.
// Checked before portServiceMap so a server's self-reported protocol identity
// takes precedence over the port number (e.g. SSH on a non-standard port).
var bannerHints = []struct {
	keyword string
	service string
}{
	{"SSH-", "SSH"},
	{"HTTP/", "HTTP"},
	{"SMTP", "SMTP"},
	{"ESMTP", "SMTP"},
	{"FTP", "FTP"},
	{"+OK ", "POP3"},
	{"POP3", "POP3"},
	{"IMAP", "IMAP"},
	{"MYSQL", "MySQL"},
	{"MARIADB", "MySQL"},
	{"REDIS", "Redis"},
	{"POSTGRESQL", "PostgreSQL"},
	{"MONGODB", "MongoDB"},
	{"LDAP", "LDAP"},
	{"MEMCACHED", "Memcached"},
}

// GrabBanner dials ip:port over TCP, waits up to timeout for the remote end to
// send data, and returns the first bannerReadSize bytes with non-printable
// characters stripped. Returns an empty string when the connection fails, the
// server sends nothing before the deadline, or timeout is exceeded.
//
// This function uses a plain TCP connect and requires no elevated privileges.
// The parent ctx is respected: if it is cancelled before the dial completes,
// an empty string is returned immediately.
func GrabBanner(ctx context.Context, ip string, port uint16, timeout time.Duration) string {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set an absolute deadline for the read so the goroutine cannot block
	// indefinitely if the server accepts the connection but sends nothing.
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}

	buf := make([]byte, bannerReadSize)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}

	return cleanBanner(buf[:n])
}

// ServiceHint returns the probable service name for the given port and banner.
// The banner is checked first (case-insensitive keyword match) because a server
// may run on a non-standard port; the port-number map is used as a fallback.
// Returns an empty string when neither the banner nor the port is recognised.
func ServiceHint(port uint16, banner string) string {
	upper := strings.ToUpper(banner)
	for _, h := range bannerHints {
		if strings.Contains(upper, h.keyword) {
			return h.service
		}
	}
	return portServiceMap[port]
}

// cleanBanner removes bytes that would corrupt terminal output: everything
// below 0x20 is dropped except the whitespace characters \t, \r, and \n, which
// preserve multi-line banner formatting. DEL (0x7f) and high bytes are also
// removed. The result is trimmed of leading/trailing whitespace.
func cleanBanner(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7e) {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
}
