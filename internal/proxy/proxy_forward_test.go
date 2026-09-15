package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
)

// testProxyConfig 返回一份只保留必要项的配置。
// 缓存与威胁扫描都取零值（关闭），避免本组用例的结果受其它模块影响。
func testProxyConfig() *cfgpkg.Config {
	return &cfgpkg.Config{
		ProxyName:  "Test-Proxy",
		EnableMITM: true,
	}
}

// newProxyServer 启动一个把 Proxy 当作 http.Handler 使用的代理服务器。
func newProxyServer(t *testing.T, p *Proxy) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	return server
}

// newProxyClient 返回一个所有请求都经由指定代理的 http.Client。
func newProxyClient(t *testing.T, proxyAddr string, tlsConfig *tls.Config) *http.Client {
	t.Helper()
	parsed, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatalf("解析代理地址失败: %v", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(parsed)}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// recordedRequest 是上游看到的请求快照。
type recordedRequest struct {
	Method string
	Host   string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

// requestRecorder 线程安全地收集上游收到的请求，供断言使用。
type requestRecorder struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

func (r *requestRecorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, recordedRequest{
			Method: req.Method,
			Host:   req.Host,
			Path:   req.URL.Path,
			Query:  req.URL.RawQuery,
			Header: req.Header.Clone(),
			Body:   string(body),
		})
		r.mu.Unlock()
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello from upstream"))
	}
}

func (r *requestRecorder) last(t *testing.T) recordedRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		t.Fatalf("上游没有收到任何请求")
	}
	return r.reqs[len(r.reqs)-1]
}

// TestHTTPProxyForwardsRequest 覆盖主线场景"配置代理 → 访问 HTTP 网站 → 成功转发"：
// 方法、路径、查询串、请求体与自定义首部要原样到达上游，上游响应也要原样回到客户端。
func TestHTTPProxyForwardsRequest(t *testing.T) {
	recorder := &requestRecorder{}
	upstream := httptest.NewServer(recorder.handler())
	defer upstream.Close()

	proxyServer := newProxyServer(t, New(nil, testProxyConfig()))
	client := newProxyClient(t, proxyServer.URL, nil)

	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/api/items?page=2&size=10", strings.NewReader("request-payload"))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Client-Tag", "abc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("经代理访问上游失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("状态码 = %d, 期望 %d", resp.StatusCode, http.StatusCreated)
	}
	if string(body) != "hello from upstream" {
		t.Fatalf("响应体 = %q", body)
	}
	if got := resp.Header.Get("X-Upstream"); got != "yes" {
		t.Fatalf("上游自定义响应头被丢失: %q", got)
	}

	got := recorder.last(t)
	if got.Method != http.MethodPost {
		t.Fatalf("上游收到的方法 = %q, 期望 POST", got.Method)
	}
	if got.Path != "/api/items" || got.Query != "page=2&size=10" {
		t.Fatalf("上游收到的路径/查询串 = %q?%q", got.Path, got.Query)
	}
	if got.Body != "request-payload" {
		t.Fatalf("上游收到的请求体 = %q", got.Body)
	}
	if got.Header.Get("X-Client-Tag") != "abc" {
		t.Fatalf("上游丢失了自定义请求头: %+v", got.Header)
	}
	if got.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("上游丢失了 Content-Type: %+v", got.Header)
	}
	// 上游应当看到自己的主机名，而不是代理的地址
	if want := strings.TrimPrefix(upstream.URL, "http://"); got.Host != want {
		t.Fatalf("上游收到的 Host = %q, 期望 %q", got.Host, want)
	}
}

// TestHTTPProxyStripsHopByHopAndProxyAuth 验证逐跳首部与代理认证信息不会被转发给上游。
// 这两类首部只对单次连接有意义，泄漏出去既破坏语义，也会暴露代理凭据。
func TestHTTPProxyStripsHopByHopAndProxyAuth(t *testing.T) {
	recorder := &requestRecorder{}
	upstream := httptest.NewServer(recorder.handler())
	defer upstream.Close()

	p := New(nil, testProxyConfig())

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/hop", nil)
	req.Header.Set("X-Keep-Me", "kept")
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Connection", "X-Drop-Me")
	req.Header.Set("X-Drop-Me", "should-not-reach-upstream")

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	// 上游固定返回 201，这里顺带确认状态码被原样透传
	if rr.Code != http.StatusCreated {
		t.Fatalf("状态码 = %d, 期望 201; body=%s", rr.Code, rr.Body.String())
	}

	got := recorder.last(t)
	if got.Header.Get("X-Keep-Me") != "kept" {
		t.Fatalf("普通请求头不应被删除: %+v", got.Header)
	}
	for _, name := range []string{"Proxy-Authorization", "Keep-Alive", "Connection", "X-Drop-Me"} {
		if value := got.Header.Get(name); value != "" {
			t.Fatalf("首部 %s 不应转发给上游，实际值 = %q", name, value)
		}
	}
}

// TestHTTPProxyBlocksDomainFromPolicy 验证黑白名单能按域名精准拦截。
func TestHTTPProxyBlocksDomainFromPolicy(t *testing.T) {
	recorder := &requestRecorder{}
	upstream := httptest.NewServer(recorder.handler())
	defer upstream.Close()

	cfg := testProxyConfig()
	cfg.BlockedDomains = []string{"blocked.test"}
	cfg.BlockResponseStatus = http.StatusForbidden
	p := New(nil, cfg)

	// 直连上游的地址不在黑名单里，应当正常放行
	allowed := httptest.NewRequest(http.MethodGet, upstream.URL+"/ok", nil)
	allowedRR := httptest.NewRecorder()
	p.ServeHTTP(allowedRR, allowed)
	if allowedRR.Code != http.StatusCreated {
		t.Fatalf("未命中的域名应放行，状态码 = %d", allowedRR.Code)
	}

	// 命中黑名单的域名应当在访问上游之前就被拦截
	blocked := httptest.NewRequest(http.MethodGet, "http://blocked.test/secret", nil)
	blockedRR := httptest.NewRecorder()
	p.ServeHTTP(blockedRR, blocked)

	if blockedRR.Code != http.StatusForbidden {
		t.Fatalf("命中黑名单应返回 403, 实际 = %d", blockedRR.Code)
	}
	if !strings.Contains(blockedRR.Body.String(), "blocked") {
		t.Fatalf("拦截页面未提示被拦截: %s", blockedRR.Body.String())
	}
	if got := recorder.last(t).Path; got != "/ok" {
		t.Fatalf("被拦截的请求不应到达上游，上游最后一次收到的是 %q", got)
	}
}

// TestHTTPProxyBlocksPortFromPolicy 验证端口黑名单。
func TestHTTPProxyBlocksPortFromPolicy(t *testing.T) {
	cfg := testProxyConfig()
	cfg.BlockedPorts = []int{8080}
	p := New(nil, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://example.test:8080/", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("命中端口黑名单应返回 403, 实际 = %d", rr.Code)
	}
}

// TestHTTPProxyBlocksIPFromPolicy 验证 IP 黑名单。
// 这里的地址是本地回环地址，命中 blocked_ips 后必须在上游被访问之前拦截。
func TestHTTPProxyBlocksIPFromPolicy(t *testing.T) {
	recorder := &requestRecorder{}
	upstream := httptest.NewServer(recorder.handler())
	defer upstream.Close()

	cfg := testProxyConfig()
	cfg.BlockedIPs = []string{"127.0.0.0/8"}
	p := New(nil, cfg)

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/blocked-by-ip", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("命中 IP 黑名单应返回 403, 实际 = %d", rr.Code)
	}
	recorder.mu.Lock()
	reached := len(recorder.reqs)
	recorder.mu.Unlock()
	if reached != 0 {
		t.Fatalf("被 IP 规则拦截的请求不应到达上游，实际上游收到 %d 个请求", reached)
	}
}
