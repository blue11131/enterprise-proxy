package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

// CA 表示本地证书颁发机构，用于为每个被拦截的域名签发叶子证书。
// 客户端只要信任本 CA，代理就能解密并审计 HTTPS 流量。
type CA struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey // 实际为 *rsa.PrivateKey
}

// LoadOrCreate 按配置中的路径加载已有 CA；若文件不存在则生成一份新的并落盘。
// 配置为空时回退到 CACertOutputPath / CAKeyOutputPath，保证首次启动与后续启动使用同一份 CA。
func LoadOrCreate(config *cfgpkg.Config) (*CA, error) {
	// 确定用于读取的路径
	certPath := config.CACertPath
	keyPath := config.CAKeyPath

	if certPath == "" {
		certPath = config.CACertOutputPath
	}

	if keyPath == "" {
		keyPath = config.CAKeyOutputPath
	}

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		log.Printf("Loading existing CA from %s / %s", certPath, keyPath)

		return parseCA(certPEM, keyPEM)
	}

	log.Printf("CA files not found, generating new CA...")

	ca, err := generateCA()

	if err != nil {
		return nil, err
	}

	if err := saveCA(config.CACertOutputPath, config.CAKeyOutputPath, ca); err != nil {
		return nil, err
	}

	return ca, nil
}

// LoadFromFiles 从指定路径读取证书与私钥，供管理员在控制台替换 CA 时使用。
func LoadFromFiles(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	return parseCA(certPEM, keyPEM)
}

// Rotate 重新生成一份 CA 并覆盖落盘文件，旧证书签发的叶子证书随即失效。
func Rotate(config *cfgpkg.Config) (*CA, error) {
	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	if err := saveCA(config.CACertOutputPath, config.CAKeyOutputPath, ca); err != nil {
		return nil, err
	}
	return ca, nil
}

// parseCA 解析 PEM 格式的 CA 证书与私钥。
func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)

	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	priv, err := parseRSAPrivateKey(keyBlock.Bytes)

	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{Cert: cert, Key: priv}, nil
}

// parseRSAPrivateKey 解析两种常见的私钥编码：
// PKCS#1（"RSA PRIVATE KEY"，本模块 saveCA 写出的格式）与
// PKCS#8（"PRIVATE KEY"，OpenSSL 3.x 默认生成的格式）。
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if priv, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return priv, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not RSA private key")
	}
	return priv, nil
}

// generateCA 生成自签名的根证书，私钥长度 3072 位，有效期 5 年。
func generateCA() (*CA, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Go MITM Proxy CA",
			Organization: []string{"Go MITM Proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour), // 回拨 1 小时，容忍客户端与服务器的时钟偏差
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse created CA cert: %w", err)
	}

	return &CA{Cert: cert, Key: priv}, nil
}

// saveCA 将 CA 证书与私钥以 PEM 形式写入磁盘，必要时先创建上级目录。
func saveCA(certPath, keyPath string, ca *CA) error {
	priv, ok := ca.Key.(*rsa.PrivateKey)

	if !ok {
		return fmt.Errorf("CA key is not RSA private key")
	}

	if dir := filepath.Dir(certPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create cert directory: %w", err)
		}
	}

	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create key directory: %w", err)
		}
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create CA cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}); err != nil {
		return fmt.Errorf("write CA cert PEM: %w", err)
	}

	log.Printf("Wrote CA certificate to %s", certPath)

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("create CA key file: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("write CA key PEM: %w", err)
	}

	log.Printf("Wrote CA private key to %s", keyPath)

	return nil
}

// GenerateCertForHost 为指定主机动态签发一张由本 CA 签名的叶子证书。
// 这是 HTTPS 中间人解密的关键：每个被拦截的域名都会拿到一张浏览器信任的证书。
// 传入的 host 可以带端口（例如 "example.com:443"），端口会被自动去掉。
func (ca *CA) GenerateCertForHost(host string) (tls.Certificate, error) {
	// 去掉可能存在的端口
	h := host

	if strings.Contains(host, ":") {
		if name, _, err := net.SplitHostPort(host); err == nil {
			h = name
		} else if i := strings.LastIndex(host, ":"); i != -1 {
			// 无端口的 IPv6 字面量（如 "::1"）保持原值，其余按最后一个冒号切分
			if ip := net.ParseIP(host); ip == nil {
				h = host[:i]
			}
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: h},
		NotBefore:             time.Now().Add(-time.Hour), // 回拨一小时，容忍双方时钟偏差
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 主机名写入 DNS SAN，IP 字面量写入 IP SAN；证书校验以 SAN 为准
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{h}
	}

	parent := ca.Cert
	caPriv, ok := ca.Key.(*rsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("CA key not RSA")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, caPriv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create leaf cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create X509KeyPair: %w", err)
	}

	// 把解析后的叶子证书挂到 Leaf 上，便于调用方直接读取 SAN、有效期等信息用于审计
	if parsed, err := x509.ParseCertificate(derBytes); err == nil {
		leaf.Leaf = parsed
	}

	return leaf, nil
}
