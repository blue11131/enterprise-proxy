package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	capkg "mitm-proxy/internal/ca"
	cfgpkg "mitm-proxy/internal/config"
)

// newTestCA 在临时目录生成一份本地 CA，并返回一个用于信任它的 CertPool，
// 模拟客户端安装了代理根证书之后的状态。
func newTestCA(t *testing.T) (*capkg.CA, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	ca, err := capkg.LoadOrCreate(&cfgpkg.Config{
		CACertOutputPath: filepath.Join(dir, "ca-cert.pem"),
		CAKeyOutputPath:  filepath.Join(dir, "ca-key.pem"),
	})
	if err != nil {
		t.Fatalf("生成测试 CA 失败: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return ca, pool
}

// redirectDialer 把发往任意地址的连接都改写到本地测试服务器，
// 让测试里的 https://example.test 能落到 httptest 启动的上游。
// 真实环境下这一步由 DNS 完成。
func redirectDialer(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, addr)
	}
}

// TestMITMDecryptsHTTPSThroughConnect 覆盖主线场景
// "配置代理 → 访问 HTTPS 网站 → 成功转发"，并验证流量确实被解密审计。
//
// 客户端信任测试 CA，因此它拿到的是代理为该域名现场签发的叶子证书；
// 上游则是代理以明文形式转发过去的，说明中间人解密链路完整可用。
func TestMITMDecryptsHTTPSThroughConnect(t *testing.T) {
	type upstreamHit struct {
		Method string
		Host   string
		Path   string
		IsTLS  bool
	}
	hits := make(chan upstreamHit, 1)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hits <- upstreamHit{Method: r.Method, Host: r.Host, Path: r.URL.Path, IsTLS: r.TLS != nil}:
		default:
		}
		w.Header().Set("X-Upstream", "yes")
		_, _ = w.Write([]byte("secret over https"))
	}))
	defer upstream.Close()

	ca, roots := newTestCA(t)
	p := New(ca, testProxyConfig())

	// 上游用的是 httptest 的自签证书。这里注入一个仅供测试使用的客户端，
	// 把代理的上游连接改写到本地测试服务器并跳过上游证书校验——
	// 本用例验证的是代理自身的中间人解密能力，而不是上游证书校验策略。
	p.client.Store(&http.Client{Transport: &http.Transport{
		DialContext:     redirectDialer(upstream.Listener.Addr().String()),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 仅测试使用
	}})

	proxyServer := newProxyServer(t, p)
	client := newProxyClient(t, proxyServer.URL, &tls.Config{
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"}, // 固定走 HTTP/1.1 中间人分支
	})

	resp, err := client.Get("https://example.test/hello")
	if err != nil {
		t.Fatalf("经代理访问 HTTPS 上游失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", resp.StatusCode)
	}
	if string(body) != "secret over https" {
		t.Fatalf("响应体 = %q", body)
	}
	if got := resp.Header.Get("X-Upstream"); got != "yes" {
		t.Fatalf("上游自定义响应头被丢失: %q", got)
	}

	// 客户端看到的证书必须是代理为 example.test 现场签发的，否则说明没有解密
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("响应未携带对端证书，无法确认中间人解密已生效")
	}
	if got := resp.TLS.PeerCertificates[0].Subject.CommonName; got != "example.test" {
		t.Fatalf("客户端看到的证书 CN = %q, 期望 example.test", got)
	}

	select {
	case hit := <-hits:
		if hit.Method != http.MethodGet || hit.Host != "example.test" || hit.Path != "/hello" {
			t.Fatalf("上游收到的请求异常: %+v", hit)
		}
		// 代理与上游之间应当重新建立 TLS，而不是明文回源
		if !hit.IsTLS {
			t.Fatalf("代理回源时未使用 TLS: %+v", hit)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("上游没有收到请求")
	}
}

// TestMITMHandlesHTTP2ThroughConnect 验证 ALPN 协商为 h2 时走 HTTP/2 中间人分支。
func TestMITMHandlesHTTP2ThroughConnect(t *testing.T) {
	hits := make(chan string, 1)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hits <- r.URL.Path:
		default:
		}
		_, _ = w.Write([]byte("h2 body"))
	}))
	defer upstream.Close()

	ca, roots := newTestCA(t)
	cfg := testProxyConfig()
	cfg.TLSNextProtos = []string{"h2", "http/1.1"}
	p := New(ca, cfg)
	p.client.Store(&http.Client{Transport: &http.Transport{
		DialContext:     redirectDialer(upstream.Listener.Addr().String()),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 仅测试使用
	}})

	proxyServer := newProxyServer(t, p)
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("解析代理地址失败: %v", err)
	}
	transport := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
	}
	t.Cleanup(transport.CloseIdleConnections)

	resp, err := (&http.Client{Transport: transport}).Get("https://example.test/h2")
	if err != nil {
		t.Fatalf("经代理访问 HTTPS/2 上游失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "h2 body" {
		t.Fatalf("HTTP/2 响应异常: status=%d body=%q", resp.StatusCode, body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("客户端协议 = %s, 期望 HTTP/2", resp.Proto)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("响应未携带对端证书，无法确认中间人解密已生效")
	}
	if got := resp.TLS.PeerCertificates[0].Subject.CommonName; got != "example.test" {
		t.Fatalf("客户端看到的证书 CN = %q, 期望 example.test", got)
	}

	select {
	case path := <-hits:
		if path != "/h2" {
			t.Fatalf("上游收到的路径 = %q", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("上游没有收到请求")
	}
}

// TestConnectTunnelForNonStandardPortDoesNotMITM 验证非 443 端口不做中间人解密。
//
// 客户端只信任上游自己的自签证书、不信任代理 CA：
// 一旦代理擅自解密，TLS 校验就会失败，本用例随即报错。
func TestConnectTunnelForNonStandardPortDoesNotMITM(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "end-to-end tls")
	}))
	defer upstream.Close()

	ca, _ := newTestCA(t)
	p := New(ca, testProxyConfig())
	proxyServer := newProxyServer(t, p)

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	client := newProxyClient(t, proxyServer.URL, &tls.Config{RootCAs: upstreamRoots})

	// upstream.URL 形如 https://127.0.0.1:随机端口，端口不为 443，应走明文隧道
	resp, err := client.Get(upstream.URL + "/raw-tunnel")
	if err != nil {
		t.Fatalf("经代理隧道访问上游失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "end-to-end tls" {
		t.Fatalf("隧道响应异常: status=%d body=%q", resp.StatusCode, body)
	}
	// 客户端看到的必须是上游自身的证书，而不是代理 CA 签发的叶子证书，
	// 这样才能确认代理确实只做了透传、没有解密。
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("响应未携带对端证书")
	}
	if !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, upstream.Certificate().Raw) {
		t.Fatalf("客户端看到的不是上游自身的证书，说明代理插入了解密证书: %+v", resp.TLS.PeerCertificates[0].Subject)
	}
}

// TestCONNECTRequiresHijacker 验证底层连接不可接管时返回明确错误，
// 而不是静默地建立一条无法使用的隧道。
func TestCONNECTRequiresHijacker(t *testing.T) {
	p := New(nil, testProxyConfig())

	req := httptest.NewRequest(http.MethodConnect, "http://example.test/", nil)
	req.Host = "example.test:443"
	// httptest.ResponseRecorder 没有实现 http.Hijacker
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("状态码 = %d, 期望 500", rr.Code)
	}
}
