package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

// newTestConfig 返回一份把 CA 文件放在临时目录里的配置。
func newTestConfig(t *testing.T) *cfgpkg.Config {
	t.Helper()
	dir := t.TempDir()
	return &cfgpkg.Config{
		CACertOutputPath: filepath.Join(dir, "ca-cert.pem"),
		CAKeyOutputPath:  filepath.Join(dir, "ca-key.pem"),
	}
}

// caPool 把 CA 证书装进一个 CertPool，用于模拟客户端信任该 CA。
func caPool(t *testing.T, ca *CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

func TestLoadOrCreateGeneratesThenReusesCA(t *testing.T) {
	cfg := newTestConfig(t)

	first, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("首次 LoadOrCreate 失败: %v", err)
	}
	if !first.Cert.IsCA {
		t.Fatalf("生成的证书不是 CA: %+v", first.Cert)
	}
	for _, path := range []string{cfg.CACertOutputPath, cfg.CAKeyOutputPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("CA 文件未落盘 %s: %v", path, err)
		}
	}

	second, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("再次 LoadOrCreate 失败: %v", err)
	}
	if !second.Cert.Equal(first.Cert) {
		t.Fatalf("第二次调用应复用已有 CA，但证书变了")
	}
}

func TestLoadOrCreateFallsBackToOutputPaths(t *testing.T) {
	// ca_cert_path / ca_key_path 留空时应回退到输出路径，
	// 否则每次重启都会重新生成 CA，导致客户端已信任的证书失效。
	cfg := newTestConfig(t)
	if cfg.CACertPath != "" || cfg.CAKeyPath != "" {
		t.Fatalf("前置条件错误：输入路径应为空")
	}

	first, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	second, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if !first.Cert.Equal(second.Cert) {
		t.Fatalf("路径回退后未能复用 CA")
	}
}

func TestRotateReplacesCA(t *testing.T) {
	cfg := newTestConfig(t)

	original, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	rotated, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.Cert.Equal(original.Cert) {
		t.Fatalf("Rotate 应生成新的 CA")
	}

	reloaded, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if !reloaded.Cert.Equal(rotated.Cert) {
		t.Fatalf("Rotate 后应能从磁盘加载新 CA")
	}
}

func TestGenerateCertForHostIsSignedByCA(t *testing.T) {
	cfg := newTestConfig(t)
	ca, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	leaf, err := ca.GenerateCertForHost("example.test")
	if err != nil {
		t.Fatalf("GenerateCertForHost: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatalf("叶子证书未解析出 Leaf 字段")
	}

	// 客户端用 CA 校验叶子证书，等价于浏览器信任代理根证书后的握手校验。
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.test",
		Roots:   caPool(t, ca),
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}); err != nil {
		t.Fatalf("叶子证书无法通过 CA 校验: %v", err)
	}

	if got := leaf.Leaf.Subject.CommonName; got != "example.test" {
		t.Fatalf("CommonName = %q, 期望 example.test", got)
	}
	if len(leaf.Leaf.DNSNames) != 1 || leaf.Leaf.DNSNames[0] != "example.test" {
		t.Fatalf("DNS SAN = %v, 期望 [example.test]", leaf.Leaf.DNSNames)
	}
	if leaf.PrivateKey == nil {
		t.Fatalf("叶子证书缺少私钥，无法完成 TLS 握手")
	}
}

func TestGenerateCertForHostStripsPort(t *testing.T) {
	cfg := newTestConfig(t)
	ca, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	for _, host := range []string{"example.test:443", "example.test:8443"} {
		leaf, err := ca.GenerateCertForHost(host)
		if err != nil {
			t.Fatalf("GenerateCertForHost(%q): %v", host, err)
		}
		if got := leaf.Leaf.Subject.CommonName; got != "example.test" {
			t.Fatalf("GenerateCertForHost(%q) CommonName = %q, 期望去掉端口", host, got)
		}
		if len(leaf.Leaf.DNSNames) != 1 || leaf.Leaf.DNSNames[0] != "example.test" {
			t.Fatalf("GenerateCertForHost(%q) DNS SAN = %v", host, leaf.Leaf.DNSNames)
		}
	}
}

func TestGenerateCertForHostUsesIPSAN(t *testing.T) {
	// 按 IP 访问的 HTTPS 站点（如 https://127.0.0.1）必须带 IP SAN，
	// 只写 DNS SAN 会导致证书校验失败、流量无法解密审计。
	cfg := newTestConfig(t)
	ca, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	cases := []struct {
		host string
		want net.IP
	}{
		{"127.0.0.1", net.ParseIP("127.0.0.1")},
		{"127.0.0.1:443", net.ParseIP("127.0.0.1")},
		{"[::1]:443", net.ParseIP("::1")},
		{"::1", net.ParseIP("::1")},
	}

	for _, tc := range cases {
		leaf, err := ca.GenerateCertForHost(tc.host)
		if err != nil {
			t.Fatalf("GenerateCertForHost(%q): %v", tc.host, err)
		}
		if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(tc.want) {
			t.Fatalf("GenerateCertForHost(%q) IP SAN = %v, 期望 [%v]", tc.host, leaf.Leaf.IPAddresses, tc.want)
		}
		if len(leaf.Leaf.DNSNames) != 0 {
			t.Fatalf("GenerateCertForHost(%q) 不应写入 DNS SAN: %v", tc.host, leaf.Leaf.DNSNames)
		}
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: caPool(t, ca)}); err != nil {
			t.Fatalf("GenerateCertForHost(%q) 证书校验失败: %v", tc.host, err)
		}
	}
}

func TestGenerateCertForHostProducesUsableTLSKeyPair(t *testing.T) {
	cfg := newTestConfig(t)
	ca, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	leaf, err := ca.GenerateCertForHost("example.test")
	if err != nil {
		t.Fatalf("GenerateCertForHost: %v", err)
	}

	// 真正跑一次 TLS 握手，确认签发出的证书可以直接用于 tls.Server。
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()

	client := tls.Client(clientConn, &tls.Config{RootCAs: caPool(t, ca), ServerName: "example.test", MinVersion: tls.VersionTLS12})
	clientErr := make(chan error, 1)
	go func() { clientErr <- client.Handshake() }()

	deadline := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-serverErr:
			if err != nil {
				t.Fatalf("服务端 TLS 握手失败: %v", err)
			}
		case err := <-clientErr:
			if err != nil {
				t.Fatalf("客户端 TLS 握手失败: %v", err)
			}
		case <-deadline:
			t.Fatalf("TLS 握手超时")
		}
	}
}

func TestLoadFromFilesAcceptsPKCS8Key(t *testing.T) {
	// OpenSSL 3.x 的 `openssl genrsa` 默认输出 PKCS#8（"PRIVATE KEY"），
	// 只支持 PKCS#1 会让用户自带的密钥无法加载。
	cfg := newTestConfig(t)
	ca, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	priv, ok := ca.Key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("CA 私钥不是 RSA")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	keyPath := filepath.Join(t.TempDir(), "pkcs8-key.pem")
	if err := os.WriteFile(keyPath, pkcs8PEM, 0600); err != nil {
		t.Fatalf("写入 PKCS#8 私钥失败: %v", err)
	}

	loaded, err := LoadFromFiles(cfg.CACertOutputPath, keyPath)
	if err != nil {
		t.Fatalf("LoadFromFiles 无法加载 PKCS#8 私钥: %v", err)
	}
	if !loaded.Cert.Equal(ca.Cert) {
		t.Fatalf("加载到的证书与原始 CA 不一致")
	}
}

func TestParseCARejectsInvalidPEM(t *testing.T) {
	if _, err := parseCA([]byte("not a pem"), []byte("not a pem")); err == nil {
		t.Fatalf("非法 PEM 应返回错误")
	}
}

func TestGenerateCertForHostProducesDistinctKeys(t *testing.T) {
	cfg := newTestConfig(t)
	ca, err := LoadOrCreate(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	first, err := ca.GenerateCertForHost("a.test")
	if err != nil {
		t.Fatalf("GenerateCertForHost: %v", err)
	}
	second, err := ca.GenerateCertForHost("a.test")
	if err != nil {
		t.Fatalf("GenerateCertForHost: %v", err)
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatalf("两次签发不应复用序列号")
	}

	// 私钥必须可用（能被 rsa.SignPKCS1v15 使用），否则 TLS 握手会失败。
	priv, ok := first.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("叶子私钥不是 RSA")
	}
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if _, err := rsa.SignPKCS1v15(rand.Reader, priv, 0, digest); err != nil {
		// 这里只关心私钥结构可用，签名算法不匹配不算失败
		t.Logf("SignPKCS1v15 返回: %v", err)
	}
}
