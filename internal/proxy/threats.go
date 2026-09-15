package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"mitm-proxy/internal/access"
	"mitm-proxy/internal/config"
	"mitm-proxy/internal/policy"
	"mitm-proxy/internal/threats"
)

// scanRequest 采样请求体并交给威胁扫描器判定。
// 同时承担流量取证：即使未开启扫描，只要开启了请求体留存也会采样上报。
func (p *Proxy) scanRequest(ctx context.Context, r *http.Request) (threats.ThreatVerdict, error) {
	cfg := p.cfg().ThreatScanner
	threatScan := p.threats != nil && cfg.Enabled && cfg.ScanRequests
	bodyCapture := p.cfg().TrafficCapture.StoreBodies
	if !threatScan && !bodyCapture {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}

	limit := bodySampleLimit(cfg.MaxBodyBytes, p.cfg().TrafficCapture.MaxBodyBytes)
	sample, err := sampleRequestBody(r, limit)
	if err != nil {
		return threats.ThreatVerdict{}, err
	}
	p.captureTrafficBody(ctx, "request", sample)
	if !threatScan {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}
	scanSample := truncateSample(sample, cfg.MaxBodyBytes)
	input := threats.ScanInput{
		Target:      threats.ScanRequest,
		Method:      r.Method,
		URL:         r.URL.String(),
		Host:        r.Host,
		Headers:     threats.HeaderMap(r.Header),
		ContentType: r.Header.Get("Content-Type"),
		BodySample:  scanSample,
		BodyHash:    threats.BodyHash(scanSample),
		RemoteIP:    remoteIP(r.RemoteAddr),
	}
	if input.Host == "" {
		input.Host = r.URL.Host
	}
	return p.threats.ScanRequest(ctx, input)
}

// prepareRequestForThreatResponseScan 在开启响应扫描时改写请求的条件请求首部。
//
// 带条件的浏览器请求可能让源站返回无响应体的 304，这会保留浏览器缓存行为，
// 但也让响应扫描器无从判断内容。因此开启响应扫描时强制要求完整响应。
func (p *Proxy) prepareRequestForThreatResponseScan(r *http.Request) {
	cfg := p.cfg().ThreatScanner
	if !cfg.Enabled || !cfg.ScanResponses {
		return
	}

	for _, header := range []string{
		"If-None-Match",
		"If-Modified-Since",
		"If-Match",
		"If-Unmodified-Since",
		"If-Range",
		"Range",
	} {
		r.Header.Del(header)
	}
	r.Header.Set("Cache-Control", "no-cache")
}

// prepareResponseForScan 处理需要流式转发的响应：按需读取前若干字节做扫描，
// 再把已读部分与剩余响应体拼回，保证客户端拿到的内容完整。
func (p *Proxy) prepareResponseForScan(ctx context.Context, req *http.Request, resp *http.Response) (threats.ThreatVerdict, error) {
	if resp == nil || resp.Body == nil {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}
	cfg := p.cfg().ThreatScanner
	threatScan := p.threats != nil && cfg.Enabled && cfg.ScanResponses
	bodyCapture := p.cfg().TrafficCapture.StoreBodies
	if !threatScan && !bodyCapture {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}

	contentType := resp.Header.Get("Content-Type")
	// 非文本内容（图片、视频等）只按元数据判定，避免把二进制塞进分类器
	metadataOnly := !threats.IsTextLikeForProxy(cfg, contentType) && cfg.Mode != "metadata_only"
	if threatScan && !bodyCapture && metadataOnly {
		input := responseScanInput(req, resp, nil, "")
		return p.threats.ScanResponse(ctx, input)
	}

	limit := bodySampleLimit(cfg.MaxBodyBytes, p.cfg().TrafficCapture.MaxBodyBytes)
	buf, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return threats.ThreatVerdict{}, err
	}

	// 响应体未超过采样上限：整体读入后可直接复用
	if int64(len(buf)) <= limit {
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(buf))
		resp.ContentLength = int64(len(buf))
		p.captureTrafficBody(ctx, "response", buf)
		if !threatScan {
			return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
		}
		if metadataOnly {
			input := responseScanInput(req, resp, nil, "")
			return p.threats.ScanResponse(ctx, input)
		}
		scanSample := truncateSample(buf, cfg.MaxBodyBytes)
		input := responseScanInput(req, resp, scanSample, threats.BodyHash(scanSample))
		return p.threats.ScanResponse(ctx, input)
	}

	// 超出上限：只取前 limit 字节做样本，剩余内容拼回响应体继续流式转发
	sample := buf[:limit]
	p.captureTrafficBody(ctx, "response", sample)
	resp.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(bytes.NewReader(buf), resp.Body),
		Closer: resp.Body,
	}
	if !threatScan {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}
	if metadataOnly {
		input := responseScanInput(req, resp, nil, "")
		return p.threats.ScanResponse(ctx, input)
	}
	scanSample := truncateSample(sample, cfg.MaxBodyBytes)
	input := responseScanInput(req, resp, scanSample, threats.BodyHash(scanSample))
	return p.threats.ScanResponse(ctx, input)
}

// scanBufferedResponse 扫描已经整体读入内存的响应体（缓存命中或开启缓存时使用）。
func (p *Proxy) scanBufferedResponse(ctx context.Context, req *http.Request, resp *http.Response, body []byte) (threats.ThreatVerdict, error) {
	cfg := p.cfg().ThreatScanner
	threatScan := p.threats != nil && cfg.Enabled && cfg.ScanResponses
	bodyCapture := p.cfg().TrafficCapture.StoreBodies
	if !threatScan && !bodyCapture {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}
	sample := truncateSample(body, bodySampleLimit(cfg.MaxBodyBytes, p.cfg().TrafficCapture.MaxBodyBytes))
	p.captureTrafficBody(ctx, "response", sample)
	if !threatScan {
		return threats.ThreatVerdict{Action: threats.ActionAllow}, nil
	}
	sample = truncateSample(sample, cfg.MaxBodyBytes)
	input := responseScanInput(req, resp, sample, threats.BodyHash(sample))
	return p.threats.ScanResponse(ctx, input)
}

// sampleRequestBody 按 limit 读取请求体样本，并把读到的内容放回 r.Body，
// 保证后续转发给上游的请求体完整无损。
func sampleRequestBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 131072
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) <= limit {
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.ContentLength = int64(len(buf))
		return buf, nil
	}
	sample := append([]byte(nil), buf[:limit]...)
	r.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(bytes.NewReader(buf), r.Body),
		Closer: r.Body,
	}
	return sample, nil
}

// bodySampleLimit 取扫描上限与取证上限中的较大值，避免两者互相截断。
func bodySampleLimit(a, b int64) int64 {
	if a <= 0 {
		a = 131072
	}
	if b > a {
		return b
	}
	return a
}

// truncateSample 把样本截断到指定上限，limit <= 0 表示不限制。
func truncateSample(sample []byte, limit int64) []byte {
	if limit <= 0 || int64(len(sample)) <= limit {
		return sample
	}
	return sample[:limit]
}

// responseScanInput 组装响应扫描的输入结构。
func responseScanInput(req *http.Request, resp *http.Response, sample []byte, bodyHash string) threats.ScanInput {
	input := threats.ScanInput{
		Target:      threats.ScanResponse,
		Method:      req.Method,
		URL:         req.URL.String(),
		Host:        req.Host,
		StatusCode:  resp.StatusCode,
		Headers:     threats.HeaderMap(resp.Header),
		ContentType: resp.Header.Get("Content-Type"),
		BodySample:  sample,
		BodyHash:    bodyHash,
		RemoteIP:    remoteIP(req.RemoteAddr),
	}
	if input.Host == "" {
		input.Host = req.URL.Host
	}
	return input
}

// shouldBlock 结合扫描结果与错误判断是否应当拦截。
func (p *Proxy) shouldBlock(verdict threats.ThreatVerdict, err error) bool {
	return threats.ShouldBlock(verdict, err, p.cfg().ThreatScanner)
}

// writeThreatBlockedResponse 向客户端写回拦截页面。
func writeThreatBlockedResponse(w http.ResponseWriter, status int, verdict threats.ThreatVerdict) {
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(renderThreatBlockPage(status, verdict)))
}

// threatBlockedResponse 构造一份拦截页面响应，用于已接管连接（CONNECT/MITM）的场景。
func threatBlockedResponse(verdict threats.ThreatVerdict) *http.Response {
	body := renderThreatBlockPage(http.StatusForbidden, verdict)
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":   []string{"text/html; charset=utf-8"},
			"Content-Length": []string{strconv.Itoa(len(body))},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

// accessBlockedResponse 构造访问控制拒绝页面，用于已接管连接（MITM）的场景。
func accessBlockedResponse(cfg *config.Config, decision access.Decision) *http.Response {
	status, body := access.DeniedPageHTML(cfg, decision)
	return &http.Response{
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":   []string{"text/html; charset=utf-8"},
			"Cache-Control":  []string{"no-store"},
			"Content-Length": []string{strconv.Itoa(len(body))},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

// writeAccessBlockedResponse 直接向 ResponseWriter 写回访问控制拒绝页面。
func writeAccessBlockedResponse(w http.ResponseWriter, cfg *config.Config, decision access.Decision) {
	status, body := access.DeniedPageHTML(cfg, decision)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// renderThreatBlockPage 渲染拦截提示页。页面只展示分类与原因，
// 不回显原始载荷，避免用户看到被拦截的违规内容。
func renderThreatBlockPage(status int, verdict threats.ThreatVerdict) string {
	category := htmlEscape(displayValue(verdict.Category, "suspicious content"))
	reason := htmlEscape(displayValue(verdict.Reason, "The proxy blocked this request before it reached your browser."))
	action := htmlEscape(displayValue(verdict.Action, threats.ActionBlock))
	confidence := verdict.Confidence * 100
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request blocked</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f3f5f8;
      color: #121926;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 32px 16px;
      background:
        linear-gradient(180deg, rgba(255,255,255,.88), rgba(243,245,248,.94)),
        radial-gradient(circle at top left, rgba(185, 28, 28, .14), transparent 34rem);
    }
    main {
      width: min(760px, 100%%);
      border: 1px solid #d8dee8;
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 24px 70px rgba(18, 25, 38, .14);
      overflow: hidden;
    }
    .top {
      display: flex;
      gap: 16px;
      align-items: center;
      padding: 24px 28px;
      border-bottom: 1px solid #e4e8ef;
      background: #fffafa;
    }
    .mark {
      width: 44px;
      height: 44px;
      flex: 0 0 auto;
      display: grid;
      place-items: center;
      border-radius: 50%%;
      background: #b42318;
      color: #ffffff;
      font-size: 26px;
      font-weight: 800;
      line-height: 1;
    }
    h1 {
      margin: 0;
      font-size: clamp(24px, 4vw, 34px);
      line-height: 1.1;
      letter-spacing: 0;
    }
    .subtitle {
      margin: 7px 0 0;
      color: #5f6b7a;
      font-size: 15px;
    }
    .content { padding: 26px 28px 28px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .item {
      min-width: 0;
      border: 1px solid #e1e6ee;
      border-radius: 8px;
      padding: 13px 14px;
      background: #fbfcfe;
    }
    .label {
      display: block;
      margin-bottom: 5px;
      color: #667085;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .value {
      display: block;
      color: #182230;
      font-size: 16px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .reason {
      border: 1px solid #f1b8b1;
      border-left: 5px solid #b42318;
      border-radius: 8px;
      padding: 16px 18px;
      background: #fff7f5;
    }
    .reason strong {
      display: block;
      margin-bottom: 6px;
      color: #7a271a;
      font-size: 14px;
    }
    .reason p {
      margin: 0;
      color: #3f4652;
      line-height: 1.55;
    }
    .footer {
      margin-top: 18px;
      color: #667085;
      font-size: 13px;
      line-height: 1.45;
    }
    @media (max-width: 640px) {
      body { padding: 0; place-items: stretch; }
      main { min-height: 100vh; border-radius: 0; border-left: 0; border-right: 0; }
      .top, .content { padding-left: 20px; padding-right: 20px; }
      .summary { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <div class="top">
      <div class="mark">!</div>
      <div>
        <h1>Request blocked</h1>
        <p class="subtitle">MITM Proxy Threat Scanner stopped this page before it reached the browser.</p>
      </div>
    </div>
    <div class="content">
      <div class="summary">
        <div class="item"><span class="label">Category</span><span class="value">%s</span></div>
        <div class="item"><span class="label">Confidence</span><span class="value">%.0f%%</span></div>
        <div class="item"><span class="label">Action</span><span class="value">%s</span></div>
      </div>
      <div class="reason">
        <strong>Why this was blocked</strong>
        <p>%s</p>
      </div>
      <p class="footer">HTTP %d. Payload details are intentionally hidden on this page; review the admin dashboard for the detection record.</p>
    </div>
  </main>
</body>
</html>`, category, confidence, action, reason, status)
}

// displayValue 返回去掉首尾空白后的取值，为空时回退到 fallback。
func displayValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// defaultString 返回去掉首尾空白后的取值，为空时回退到 fallback。
func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// threatsFromPolicy 把黑白名单拦截结果转成统一的威胁判定结构，
// 这样策略拦截与内容扫描可以共用同一套响应渲染与事件上报。
func threatsFromPolicy(decision policy.BlockDecision) threats.ThreatVerdict {
	return threats.ThreatVerdict{
		Threat:     true,
		Confidence: 1,
		Category:   "policy",
		Reason:     decision.Reason,
		Action:     threats.ActionBlock,
		Signals:    []string{decision.RuleID},
	}
}

// remoteIP 从 "ip:port" 形式的地址中取出 IP；解析失败时原样返回。
func remoteIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// htmlEscape 转义 HTML 特殊字符，防止拦截页面被注入。
func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return replacer.Replace(value)
}
