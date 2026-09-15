package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/policy"
	"mitm-proxy/internal/store"
	"mitm-proxy/internal/upstream"
)

// ResilienceStore 提供主机档案与故障注入规则的查询能力。
type ResilienceStore interface {
	MatchFaultInjectionRule(context.Context, string, store.RequestMatch) (store.FaultInjectionRule, bool, error)
	MatchHostProfile(context.Context, store.RequestMatch) (store.HostProfile, bool, error)
}

// requestFaultResult 描述故障注入产生的结果；
// Handled 为 true 时表示请求已由代理本地处理，不再访问上游。
type requestFaultResult struct {
	Handled bool
	Status  int
	Headers http.Header
	Body    []byte
	Rule    store.FaultInjectionRule
}

// effectiveConfigForRequest 计算该请求实际生效的配置。
// 未命中主机档案时返回全局配置本身，命中时返回叠加了覆盖项的副本，
// 副本与全局配置的指针不相等。
func (p *Proxy) effectiveConfigForRequest(req *http.Request) *cfgpkg.Config {
	if p.resilience == nil || req == nil {
		return p.cfg()
	}
	profile, ok, err := p.resilience.MatchHostProfile(req.Context(), requestMatchFromRequest(req))
	if err != nil || !ok {
		return p.cfg()
	}

	// 命中档案：在副本上叠加覆盖项，避免污染全局配置
	cfg := cloneProxyConfig(p.cfg())
	applyHostProfileOverrides(cfg, profile.Overrides)
	if cfg.VerboseLogging {
		p.publish(events.TopicHostProfileMatched, map[string]any{
			"profile_id":   profile.ID,
			"profile_name": profile.Name,
			"host":         req.URL.Host,
			"url":          req.URL.String(),
			"method":       req.Method,
		}, trafficID(req.Context()))
	}
	return cfg
}

// effectiveConfigForHost 与 effectiveConfigForRequest 同理，用于只有主机名的 CONNECT 阶段。
func (p *Proxy) effectiveConfigForHost(ctx context.Context, host string) *cfgpkg.Config {
	if p.resilience == nil {
		return p.cfg()
	}
	profile, ok, err := p.resilience.MatchHostProfile(ctx, store.RequestMatch{Method: http.MethodConnect, Host: host, URL: host})
	if err != nil || !ok {
		return p.cfg()
	}
	cfg := cloneProxyConfig(p.cfg())
	applyHostProfileOverrides(cfg, profile.Overrides)
	return cfg
}

// httpClientForConfig 返回该配置对应的上游客户端。
// 配置未被档案覆盖时复用共享客户端，否则按覆盖后的配置临时构造一个。
func (p *Proxy) httpClientForConfig(cfg *cfgpkg.Config) *http.Client {
	if cfg == nil || p.cfg() == cfg {
		return p.httpClient()
	}
	return upstream.NewHTTPClient(cfg, 0)
}

// checkPolicyWithConfig 执行黑白名单拦截判定。
func (p *Proxy) checkPolicyWithConfig(cfg *cfgpkg.Config, hostPort string) policy.BlockDecision {
	if cfg == nil {
		cfg = p.cfg()
	}
	return checkPolicyConfig(cfg, hostPort)
}

// checkPolicyConfig 依次按端口、域名、IP 三项规则判定是否拦截。
func checkPolicyConfig(cfg *cfgpkg.Config, hostPort string) policy.BlockDecision {
	engine := policy.New(cfg.BlockedPorts, cfg.BlockedDomains, cfg.BlockedIPs)
	host := hostPort
	port := 0
	if strings.Contains(hostPort, ":") {
		if parsed, err := url.Parse("//" + hostPort); err == nil {
			host = parsed.Hostname()
			if parsed.Port() != "" {
				port, _ = strconv.Atoi(parsed.Port())
			}
		}
	}
	if port > 0 {
		if decision := engine.CheckPort(port); decision.Blocked {
			return decision
		}
	}
	if decision := engine.CheckDomain(host); decision.Blocked {
		return decision
	}
	// IP 黑名单：仅在配置了规则时才做主机名解析
	if len(cfg.BlockedIPs) > 0 {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return engine.CheckIP(ip)
		}
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if decision := engine.CheckIP(ip); decision.Blocked {
					return decision
				}
			}
		}
	}
	return policy.BlockDecision{}
}

// applyRequestFault 在请求发往上游之前应用故障注入规则。
func (p *Proxy) applyRequestFault(ctx context.Context, req *http.Request, requestID string) requestFaultResult {
	if p.resilience == nil || req == nil {
		return requestFaultResult{}
	}
	if !p.faultsEnabledForRequest(ctx, req) {
		return requestFaultResult{}
	}
	rule, ok, err := p.resilience.MatchFaultInjectionRule(ctx, "request", requestMatchFromRequest(req))
	if err != nil || !ok {
		return requestFaultResult{}
	}
	p.publishFault(rule, "request", req, requestID, nil)
	switch rule.Action {
	case "delay":
		if rule.DelayMS > 0 {
			time.Sleep(time.Duration(rule.DelayMS) * time.Millisecond)
		}
	case "drop":
		return requestFaultResult{Handled: true, Status: http.StatusServiceUnavailable, Headers: http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}, Body: []byte("dropped by fault injection\n"), Rule: rule}
	case "synthetic_response":
		status := rule.SyntheticStatus
		if status < 100 || status > 599 {
			status = http.StatusServiceUnavailable
		}
		return requestFaultResult{Handled: true, Status: status, Headers: http.Header(rule.SyntheticHeaders).Clone(), Body: []byte(rule.SyntheticBody), Rule: rule}
	}
	return requestFaultResult{}
}

// applyBufferedResponseFault 对已整体读入内存的响应体应用故障注入规则。
func (p *Proxy) applyBufferedResponseFault(ctx context.Context, req *http.Request, resp *http.Response, body []byte, requestID string) []byte {
	if p.resilience == nil || req == nil || resp == nil {
		return body
	}
	if !p.faultsEnabledForRequest(ctx, req) {
		return body
	}
	rule, ok, err := p.resilience.MatchFaultInjectionRule(ctx, "response", requestMatchFromRequest(req))
	if err != nil || !ok {
		return body
	}
	p.publishFault(rule, "response", req, requestID, map[string]any{"status": resp.StatusCode, "bytes": len(body)})
	switch rule.Action {
	case "delay":
		if rule.DelayMS > 0 {
			time.Sleep(time.Duration(rule.DelayMS) * time.Millisecond)
		}
	case "throttle":
		if rule.ThrottleBytesPerSecond > 0 {
			time.Sleep(throttleDuration(len(body), rule.ThrottleBytesPerSecond))
		}
	case "corrupt":
		body = corruptBody(body, rule.CorruptProbability)
		resp.Header.Del("Content-Length")
	}
	return body
}

// wrapStreamingResponseFault 对需要流式转发的响应体包装故障注入行为
// （限速、损坏等只能在读取过程中生效，无法预先处理）。
func (p *Proxy) wrapStreamingResponseFault(ctx context.Context, req *http.Request, resp *http.Response, requestID string) {
	if p.resilience == nil || req == nil || resp == nil || resp.Body == nil {
		return
	}
	if !p.faultsEnabledForRequest(ctx, req) {
		return
	}
	rule, ok, err := p.resilience.MatchFaultInjectionRule(ctx, "response", requestMatchFromRequest(req))
	if err != nil || !ok {
		return
	}
	p.publishFault(rule, "response", req, requestID, map[string]any{"status": resp.StatusCode})
	switch rule.Action {
	case "delay":
		if rule.DelayMS > 0 {
			time.Sleep(time.Duration(rule.DelayMS) * time.Millisecond)
		}
	case "throttle":
		if rule.ThrottleBytesPerSecond > 0 {
			resp.Body = &throttledReadCloser{ReadCloser: resp.Body, bytesPerSecond: rule.ThrottleBytesPerSecond}
		}
	case "corrupt":
		resp.Body = &corruptingReadCloser{ReadCloser: resp.Body, probability: rule.CorruptProbability}
		resp.Header.Del("Content-Length")
	}
}

// faultsEnabledForRequest 判断主机档案是否关闭了故障注入，默认开启。
func (p *Proxy) faultsEnabledForRequest(ctx context.Context, req *http.Request) bool {
	if p.resilience == nil || req == nil {
		return true
	}
	profile, ok, err := p.resilience.MatchHostProfile(ctx, requestMatchFromRequest(req))
	if err != nil || !ok || profile.Overrides.EnableFaults == nil {
		return true
	}
	return *profile.Overrides.EnableFaults
}

// publishFault 上报一次故障注入事件。
func (p *Proxy) publishFault(rule store.FaultInjectionRule, phase string, req *http.Request, requestID string, extra map[string]any) {
	payload := map[string]any{
		"rule_id": rule.ID,
		"name":    rule.Name,
		"action":  rule.Action,
		"phase":   phase,
	}
	if req != nil && req.URL != nil {
		payload["method"] = req.Method
		payload["url"] = req.URL.String()
		payload["host"] = req.URL.Host
	}
	for key, value := range extra {
		payload[key] = value
	}
	p.publish(events.TopicFaultInjected, payload, requestID)
}

// requestMatchFromRequest 把请求转成规则匹配结构。
func requestMatchFromRequest(req *http.Request) store.RequestMatch {
	host := ""
	rawURL := ""
	if req != nil && req.URL != nil {
		host = req.URL.Host
		rawURL = req.URL.String()
	}
	if host == "" && req != nil {
		host = req.Host
	}
	return store.RequestMatch{Method: req.Method, URL: rawURL, Host: host}
}

// applyHostProfileOverrides 把主机档案中的覆盖项叠加到配置副本上。
func applyHostProfileOverrides(cfg *cfgpkg.Config, overrides store.HostProfileOverrides) {
	if overrides.EnableMITM != nil {
		cfg.EnableMITM = *overrides.EnableMITM
	}
	if overrides.ExcludedDomains != nil {
		cfg.ExcludedDomains = append([]string(nil), overrides.ExcludedDomains...)
	}
	if overrides.Cache != nil {
		cfg.Cache = *overrides.Cache
	}
	if overrides.TrafficCapture != nil {
		cfg.TrafficCapture = *overrides.TrafficCapture
	}
	if overrides.ThreatScanner != nil {
		cfg.ThreatScanner = *overrides.ThreatScanner
	}
	if overrides.UpstreamProxy != nil {
		cfg.UpstreamProxy = *overrides.UpstreamProxy
	}
	if overrides.BlockedPorts != nil {
		cfg.BlockedPorts = append([]int(nil), overrides.BlockedPorts...)
	}
	if overrides.BlockedDomains != nil {
		cfg.BlockedDomains = append([]string(nil), overrides.BlockedDomains...)
	}
	if overrides.BlockedIPs != nil {
		cfg.BlockedIPs = append([]string(nil), overrides.BlockedIPs...)
	}
	if overrides.VerboseLogging != nil {
		cfg.VerboseLogging = *overrides.VerboseLogging
	}
	if overrides.LogRequests != nil {
		cfg.LogRequests = *overrides.LogRequests
	}
}

// cloneProxyConfig 深拷贝配置，切片字段单独复制，避免后续修改影响全局配置。
func cloneProxyConfig(cfg *cfgpkg.Config) *cfgpkg.Config {
	if cfg == nil {
		return &cfgpkg.Config{}
	}
	clone := *cfg
	clone.ExcludedDomains = append([]string(nil), cfg.ExcludedDomains...)
	clone.BlockedPorts = append([]int(nil), cfg.BlockedPorts...)
	clone.BlockedDomains = append([]string(nil), cfg.BlockedDomains...)
	clone.BlockedIPs = append([]string(nil), cfg.BlockedIPs...)
	return &clone
}

// throttleDuration 按目标速率计算发送这些字节应当消耗的时间。
func throttleDuration(bytesCount, bytesPerSecond int) time.Duration {
	if bytesCount <= 0 || bytesPerSecond <= 0 {
		return 0
	}
	return time.Duration(float64(bytesCount) / float64(bytesPerSecond) * float64(time.Second))
}

// throttledReadCloser 通过读取后休眠来实现限速。
type throttledReadCloser struct {
	io.ReadCloser
	bytesPerSecond int
}

func (r *throttledReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		time.Sleep(throttleDuration(n, r.bytesPerSecond))
	}
	return n, err
}

// corruptingReadCloser 按概率损坏流经的字节，用于验证客户端的容错表现。
type corruptingReadCloser struct {
	io.ReadCloser
	probability float64
}

func (r *corruptingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		corruptInPlace(p[:n], r.probability)
	}
	return n, err
}

// corruptBody 返回损坏后的副本，不修改入参。
func corruptBody(body []byte, probability float64) []byte {
	out := append([]byte(nil), body...)
	corruptInPlace(out, probability)
	return out
}

// corruptInPlace 翻转首字节，probability <= 0 时视为必定损坏。
func corruptInPlace(body []byte, probability float64) {
	if len(body) == 0 {
		return
	}
	if probability <= 0 {
		probability = 1
	}
	if probability < 1 && randomFloat() > probability {
		return
	}
	body[0] ^= 0xff
}

// randomFloat 返回 [0,1) 区间的随机数；随机源不可用时返回 1（即不损坏）。
func randomFloat() float64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 1
	}
	return float64(binary.BigEndian.Uint64(buf[:])) / float64(^uint64(0))
}

// syntheticHTTPResponse 把故障注入结果构造成一个可直接写回客户端的响应。
func syntheticHTTPResponse(result requestFaultResult) *http.Response {
	headers := result.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "text/plain; charset=utf-8")
	}
	headers.Set("Content-Length", strconvItoa(len(result.Body)))
	return &http.Response{
		StatusCode: result.Status,
		Status:     strconvItoa(result.Status) + " " + http.StatusText(result.Status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     headers,
		Body:       io.NopCloser(bytes.NewReader(result.Body)),
	}
}

func strconvItoa(value int) string {
	return strconv.FormatInt(int64(value), 10)
}
