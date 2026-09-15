package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mitm-proxy/internal/access"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/threats"
)

// trafficIDContextKey 用于在请求上下文中携带本次流量的 ID，
// 使同一请求在各个环节上报的事件能够串联起来。
type trafficIDContextKey struct{}

// requestID 以纳秒时间戳作为流量 ID。
func requestID(start time.Time) string {
	return fmt.Sprintf("%d", start.UnixNano())
}

func withTrafficID(req *http.Request, id string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), trafficIDContextKey{}, id))
}

func trafficID(ctx context.Context) string {
	if id, ok := ctx.Value(trafficIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

// publishTrafficStarted 上报请求开始事件，包含请求首部与来源 IP。
func (p *Proxy) publishTrafficStarted(id string, req *http.Request, protocol string) {
	payload := map[string]any{
		"method":          req.Method,
		"url":             req.URL.String(),
		"host":            req.URL.Host,
		"protocol":        protocol,
		"remote_ip":       remoteIP(req.RemoteAddr),
		"request_headers": p.headerPayload(req.Header),
	}
	if username := access.Username(req.Context()); username != "" {
		payload["proxy_user"] = username
	}
	p.publish(events.TopicTrafficRequestStarted, payload, id)
}

// publishTrafficCompleted 上报请求完成事件，包含状态码、字节数、耗时与是否命中缓存。
func (p *Proxy) publishTrafficCompleted(id string, req *http.Request, statusCode int, bytes any, dur time.Duration, cacheHit bool, headers ...http.Header) {
	payload := map[string]any{
		"method":      req.Method,
		"url":         req.URL.String(),
		"host":        req.URL.Host,
		"status":      statusCode,
		"bytes":       bytes,
		"duration_ms": dur.Milliseconds(),
		"cache_hit":   cacheHit,
	}
	if len(headers) > 0 {
		payload["response_headers"] = p.headerPayload(headers[0])
		payload["mime_type"] = headers[0].Get("Content-Type")
	}
	if username := access.Username(req.Context()); username != "" {
		payload["proxy_user"] = username
	}
	p.publish(events.TopicTrafficResponseCompleted, payload, id)
}

// publishTunnelOpened 上报一条不解密的 CONNECT 隧道，用于审计被放行的加密流量。
func (p *Proxy) publishTunnelOpened(hostPort, protocol, remoteAddr string, usernames ...string) {
	payload := map[string]any{
		"target":    hostPort,
		"protocol":  protocol,
		"remote_ip": remoteIP(remoteAddr),
	}
	if len(usernames) > 0 && usernames[0] != "" {
		payload["proxy_user"] = usernames[0]
	}
	p.publish(events.TopicTrafficTunnelOpened, payload, "")
}

// publishBlocked 上报一次策略拦截事件。
func (p *Proxy) publishBlocked(id string, req *http.Request, ruleID, reason string) {
	payload := map[string]any{
		"method":    req.Method,
		"url":       req.URL.String(),
		"host":      req.URL.Host,
		"rule_id":   ruleID,
		"reason":    reason,
		"remote_ip": remoteIP(req.RemoteAddr),
	}
	if username := access.Username(req.Context()); username != "" {
		payload["proxy_user"] = username
	}
	p.publish(events.TopicTrafficBlocked, payload, id)
}

// publishAccessDenied 上报一次访问控制拒绝事件。
// 访问控制在请求早期执行，此时请求对象可能尚未补全信息，故逐项回退取值。
func (p *Proxy) publishAccessDenied(req *http.Request, decision access.Decision) {
	targetURL := decision.Info.URL
	if targetURL == "" && req != nil && req.URL != nil {
		targetURL = req.URL.String()
	}
	host := decision.Info.Host
	if host == "" && req != nil && req.URL != nil {
		host = req.URL.Host
	}
	method := decision.Info.Method
	if method == "" && req != nil {
		method = req.Method
	}
	remote := decision.Info.RemoteIP
	if remote == "" && req != nil {
		remote = remoteIP(req.RemoteAddr)
	}
	p.publish(events.TopicTrafficBlocked, map[string]any{
		"method":     method,
		"url":        targetURL,
		"host":       host,
		"rule_id":    defaultString(decision.RuleID, "proxy_auth"),
		"reason":     decision.Reason,
		"remote_ip":  remote,
		"proxy_user": decision.Username,
		"status":     decision.StatusCode,
	}, "")
}

// headerPayload 按取证配置整理请求/响应首部：
// 可以选择不记录首部、不记录 Cookie，并对敏感首部与 Cookie 做脱敏。
func (p *Proxy) headerPayload(headers http.Header) map[string]any {
	cfg := p.cfg().TrafficCapture
	if !cfg.StoreHeaders {
		return nil
	}
	out := make(map[string]any, len(headers))
	for name, values := range headers {
		if isCookieHeader(name) && !cfg.StoreCookies {
			continue
		}
		captured := append([]string(nil), values...)
		if stringListContainsFold(cfg.RedactedHeaders, name) {
			captured = redactedValues(captured)
		} else if isCookieHeader(name) && len(cfg.RedactedCookies) > 0 {
			captured = redactCookieHeaderValues(name, captured, cfg.RedactedCookies)
		}
		out[name] = captured
	}
	return out
}

func isCookieHeader(name string) bool {
	return strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Set-Cookie")
}

// redactedValues 把首部的所有取值替换为 [redacted]，保留取值个数以便审计。
func redactedValues(values []string) []string {
	if len(values) == 0 {
		return []string{"[redacted]"}
	}
	out := make([]string, len(values))
	for i := range out {
		out[i] = "[redacted]"
	}
	return out
}

func redactCookieHeaderValues(headerName string, values []string, redactedCookies []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.EqualFold(headerName, "Set-Cookie") {
			out = append(out, redactSetCookieValue(value, redactedCookies))
			continue
		}
		out = append(out, redactCookieValue(value, redactedCookies))
	}
	return out
}

// redactCookieValue 对 Cookie 首部中命中的键做脱敏，其余键保持不变。
func redactCookieValue(value string, redactedCookies []string) string {
	parts := strings.Split(value, ";")
	for i, part := range parts {
		name, rest, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if stringListContainsFold(redactedCookies, name) {
			prefix := ""
			if leading := leadingWhitespace(part); leading != "" {
				prefix = leading
			}
			parts[i] = prefix + name + "=[redacted]" + cookieSuffix(rest)
		}
	}
	return strings.Join(parts, ";")
}

// redactSetCookieValue 对 Set-Cookie 首部做脱敏，保留 Path/HttpOnly 等属性。
func redactSetCookieValue(value string, redactedCookies []string) string {
	name, rest, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok || !stringListContainsFold(redactedCookies, name) {
		return value
	}
	if semi := strings.Index(rest, ";"); semi >= 0 {
		return name + "=[redacted]" + rest[semi:]
	}
	return name + "=[redacted]"
}

func cookieSuffix(value string) string {
	if semi := strings.Index(value, ";"); semi >= 0 {
		return value[semi:]
	}
	return ""
}

func leadingWhitespace(value string) string {
	i := 0
	for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
		i++
	}
	return value[:i]
}

// stringListContainsFold 判断候选值是否命中列表，忽略大小写，且 "*" 表示全部命中。
func stringListContainsFold(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "*" || strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

// captureTrafficBody 按取证配置留存请求/响应体：
// 受最大长度限制，并可选择是否脱敏。
func (p *Proxy) captureTrafficBody(ctx context.Context, direction string, body []byte) {
	cfg := p.cfg().TrafficCapture
	if !cfg.StoreBodies || len(body) == 0 {
		return
	}
	id := trafficID(ctx)
	if id == "" {
		return
	}

	captured := append([]byte(nil), body...)
	if cfg.MaxBodyBytes > 0 && int64(len(captured)) > cfg.MaxBodyBytes {
		captured = captured[:cfg.MaxBodyBytes]
	}
	if cfg.RedactBodies {
		captured = threats.RedactBody(captured)
	}

	p.publish(events.TopicTrafficBodyCaptured, map[string]any{
		"direction": direction,
		"body":      string(captured),
	}, id)
}
