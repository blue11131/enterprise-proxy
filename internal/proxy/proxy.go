package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mitm-proxy/internal/access"
	capkg "mitm-proxy/internal/ca"
	cachepkg "mitm-proxy/internal/cache"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/threats"
	"mitm-proxy/internal/upstream"
)

// Proxy 是代理服务器的核心 HTTP 处理器，负责明文 HTTP 转发、
// CONNECT 隧道，以及 HTTPS 中间人解密与审计。
type Proxy struct {
	ca     *capkg.CA
	config atomic.Value // 存放 *cfgpkg.Config
	client atomic.Value // 存放 *http.Client

	mu         sync.Mutex // 保护 certCache
	certCache  map[string]*tls.Certificate
	cache      *cachepkg.Cache
	threats    *threats.Manager
	events     *events.Bus
	access     *access.Controller
	resilience ResilienceStore
}

// New 创建一个使用默认事件总线的 Proxy 实例。
func New(ca *capkg.CA, config *cfgpkg.Config) *Proxy {
	return NewWithEvents(ca, config, events.NewBus(128))
}

// NewWithEvents 创建一个 Proxy 实例，并复用外部传入的事件总线，
// 以便审计事件能被控制台等模块订阅。
func NewWithEvents(ca *capkg.CA, config *cfgpkg.Config, eventBus *events.Bus) *Proxy {
	if eventBus == nil {
		eventBus = events.NewBus(128)
	}

	p := &Proxy{
		ca:        ca,
		certCache: make(map[string]*tls.Certificate),
		cache:     cachepkg.New(config),
		events:    eventBus,
	}
	p.config.Store(config)
	p.client.Store(upstream.NewHTTPClient(config, 0))
	p.threats = threats.NewManager(p.cfg)
	p.access = access.NewController(p.cfg, nil)
	return p
}

// SetConfig 在运行时热更新代理配置。
func (p *Proxy) SetConfig(cfg *cfgpkg.Config) {
	// 使用原子替换，避免与并发读取产生数据竞争
	p.config.Store(cfg)
	p.client.Store(upstream.NewHTTPClient(cfg, 0))
	if p.cache != nil {
		p.cache.SetConfig(cfg)
	}
}

// SetCacheStore 注入本地缓存的后端存储（控制台可切换为 SQLite 等实现）。
func (p *Proxy) SetCacheStore(store cachepkg.BackingStore) {
	if p.cache != nil {
		p.cache.SetStore(store)
	}
}

// SetAccessStore 注入访问控制存储，用于加载代理用户与 ACL 规则。
func (p *Proxy) SetAccessStore(store access.Store) {
	p.access = access.NewController(p.cfg, store)
}

// cfg 安全地返回当前配置快照。
func (p *Proxy) cfg() *cfgpkg.Config {
	if v := p.config.Load(); v != nil {
		return v.(*cfgpkg.Config)
	}
	return &cfgpkg.Config{}
}

// CurrentConfig 对外暴露当前配置，供控制台与热更新逻辑读取。
func (p *Proxy) CurrentConfig() *cfgpkg.Config {
	return p.cfg()
}

// httpClient 返回当前配置对应的上游 HTTP 客户端（含连接池）。
func (p *Proxy) httpClient() *http.Client {
	if v := p.client.Load(); v != nil {
		return v.(*http.Client)
	}
	return upstream.NewHTTPClient(p.cfg(), 0)
}

func (p *Proxy) accessController() *access.Controller {
	if p.access == nil {
		p.access = access.NewController(p.cfg, nil)
	}
	return p.access
}

// ThreatScanner 返回威胁扫描器，供控制台读取规则与统计。
func (p *Proxy) ThreatScanner() *threats.Manager {
	return p.threats
}

// SetResilienceStore 注入故障注入/主机档案存储。
func (p *Proxy) SetResilienceStore(store ResilienceStore) {
	p.resilience = store
}

// EventBus 返回代理使用的事件总线。
func (p *Proxy) EventBus() *events.Bus {
	return p.events
}

// SetCA 在运行时替换 CA 证书，并清空已签发的叶子证书缓存，
// 确保旧 CA 签发的证书不会被继续复用。
func (p *Proxy) SetCA(ca *capkg.CA) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ca = ca
	p.certCache = make(map[string]*tls.Certificate)
}

// getCertForHost 返回该域名对应的叶子证书，命中缓存则直接复用，
// 未命中则用本地 CA 现场签发一张，并发布证书生成事件供审计。
func (p *Proxy) getCertForHost(host string) (*tls.Certificate, error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	if cert, ok := p.certCache[host]; ok {
		return cert, nil
	}

	if p.ca == nil {
		return nil, fmt.Errorf("proxy CA is not configured")
	}

	leaf, err := p.ca.GenerateCertForHost(host)

	if err != nil {
		return nil, err
	}

	p.certCache[host] = &leaf
	payload := map[string]any{"host": host}
	if len(leaf.Certificate) > 0 {
		if cert, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
			fingerprint := sha256.Sum256(cert.Raw)
			payload["subject"] = cert.Subject.String()
			payload["fingerprint"] = strings.ToUpper(hex.EncodeToString(fingerprint[:]))
			payload["created_at"] = cert.NotBefore.Format(time.RFC3339Nano)
			payload["expires_at"] = cert.NotAfter.Format(time.RFC3339Nano)
		}
	}
	p.publish(events.TopicCertGenerated, payload, "")

	return &leaf, nil
}

// ServeHTTP 是代理的入口：CONNECT 请求走隧道/中间人分支，其余按明文 HTTP 转发。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) logRequest(format string, args ...interface{}) {
	if p.cfg().LogRequests {
		log.Printf(format, args...)
	}
}

func (p *Proxy) logVerbose(format string, args ...interface{}) {
	if p.cfg().VerboseLogging {
		log.Printf("[VERBOSE] "+format, args...)
	}
}

// publish 向事件总线投递一条审计事件。
func (p *Proxy) publish(topic string, payload map[string]any, requestID string) {
	if p.events == nil {
		return
	}
	p.events.Publish(events.Event{
		Topic:     topic,
		Time:      time.Now().UTC(),
		Payload:   payload,
		RequestID: requestID,
	})
}

// makeCustomHeader 由代理名称派生出一个自定义请求头名：
// 全部转小写、非字母数字字符替换为连字符、加上 "x-" 前缀与给定后缀。
// 例如代理名为 "Cool Proxy" 时，suffix 为 "uid" 会得到 "x-cool-proxy-uid"。
func (p *Proxy) makeCustomHeader(suffix string) string {
	name := p.cfg().ProxyName
	// 转小写并把非字母数字字符替换为 '-'
	b := make([]rune, 0, len(name))
	prevHyphen := false

	for _, r := range name {
		// 能转换的字符统一转成小写 ASCII
		if r >= 'A' && r <= 'Z' {
			r = r + ('a' - 'A')
		}

		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b = append(b, r)
			prevHyphen = false
			continue
		}

		// 其余字符统一用一个连字符分隔（连续多个只保留一个）
		if !prevHyphen {
			b = append(b, '-')
			prevHyphen = true
		}
	}

	// 去掉首尾多余的连字符
	start := 0

	for start < len(b) && b[start] == '-' {
		start++
	}

	end := len(b)

	for end > start && b[end-1] == '-' {
		end--
	}

	token := string(b[start:end])

	if token == "" {
		token = "proxy"
	}

	return "x-" + token + "-" + suffix
}
