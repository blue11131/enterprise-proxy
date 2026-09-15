package proxy

import (
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"mitm-proxy/internal/access"
	"mitm-proxy/internal/events"
)

// mitmHTTPS2 处理 ALPN 协商结果为 HTTP/2 的 HTTPS 流量。
// 借助 http2.Server 把解密后的 h2 请求还原成普通 http.Request，
// 复用与 HTTP/1.1 相同的转发与拦截流程。
func (p *Proxy) mitmHTTPS2(clientTLS net.Conn, host, proxyUser, remoteAddr string) {
	defer clientTLS.Close()

	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := requestID(start)

		req := r.Clone(r.Context())
		req = withTrafficID(req, requestID)
		// 转发前必须清空 RequestURI
		req.RequestURI = ""

		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}

		if req.URL.Host == "" {
			if req.Host != "" {
				req.URL.Host = req.Host
			} else {
				req.URL.Host = host
			}
		}
		req.RemoteAddr = remoteAddr
		if proxyUser != "" {
			req = req.WithContext(access.WithUsername(req.Context(), proxyUser))
		}
		// 隧道在 CONNECT 阶段已完成认证，这里按已知用户复核 ACL
		accessDecision := p.accessController().AuthorizeKnownUser(req.Context(), proxyUser, remoteAddr, req.Method, req.URL.String())
		if !accessDecision.Allowed {
			p.publishAccessDenied(req, accessDecision)
			writeAccessBlockedResponse(w, p.cfg(), accessDecision)
			return
		}

		stripHopByHopHeaders(req.Header)
		p.publishTrafficStarted(requestID, req, "https/2")
		effectiveCfg := p.effectiveConfigForRequest(req)

		// 故障注入命中时直接本地构造响应
		if result := p.applyRequestFault(req.Context(), req, requestID); result.Handled {
			for k, vals := range result.Headers {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			if result.Status == 0 {
				result.Status = http.StatusServiceUnavailable
			}
			w.WriteHeader(result.Status)
			n, _ := w.Write(result.Body)
			if result.Rule.Action == "drop" {
				p.publishBlocked(requestID, req, result.Rule.ID, "dropped by fault injection")
			}
			p.publishTrafficCompleted(requestID, req, result.Status, n, time.Since(start), false, result.Headers)
			return
		}

		// 黑白名单（端口/域名/IP）拦截
		if decision := p.checkPolicyWithConfig(effectiveCfg, req.URL.Host); decision.Blocked {
			p.publishBlocked(requestID, req, decision.RuleID, decision.Reason)
			writeThreatBlockedResponse(w, effectiveCfg.BlockResponseStatus, threatsFromPolicy(decision))
			return
		}

		// 请求方向的内容安全扫描
		verdict, scanErr := p.scanRequest(req.Context(), req)
		if p.shouldBlock(verdict, scanErr) {
			writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
			return
		}
		p.prepareRequestForThreatResponseScan(req)

		// GET 等可缓存请求优先命中本地缓存
		if p.cache != nil && p.cache.ShouldConsider(req) {
			if cr, hashHex, err := p.cache.LoadContext(req.Context(), req.URL); err == nil && cr != nil {
				p.publish(events.TopicCacheHit, map[string]any{"url": req.URL.String(), "cache_key": hashHex}, requestID)
				cachedResp := &http.Response{StatusCode: cr.Status, Header: cr.Header.Clone()}
				cr.Body = p.applyBufferedResponseFault(req.Context(), req, cachedResp, cr.Body, requestID)
				verdict, scanErr := p.scanBufferedResponse(req.Context(), req, cachedResp, cr.Body)
				if p.shouldBlock(verdict, scanErr) {
					writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
					return
				}
				body := cr.Body

				for k, vv := range cachedResp.Header {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}

				// 标记该响应由本地缓存提供
				w.Header().Set("Via", p.cfg().ProxyName)

				// 附加一个由代理名派生的 UID 响应头，值为缓存文件哈希
				uidHeader := p.makeCustomHeader("uid")

				w.Header().Set(uidHeader, hashHex)
				w.WriteHeader(cachedResp.StatusCode)
				n, _ := w.Write(body)

				p.logRequest("CACHE HIT HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s", req.Method, req.URL.String(), cr.Status, n, time.Since(start))
				p.publishTrafficCompleted(requestID, req, cachedResp.StatusCode, n, time.Since(start), true, cachedResp.Header)

				return
			}
			p.publish(events.TopicCacheMiss, map[string]any{"url": req.URL.String()}, requestID)
		}

		resp, err := p.httpClientForConfig(effectiveCfg).Do(req)

		if err != nil {
			p.logVerbose("upstream HTTPS/2 error: %v", err)

			http.Error(w, "upstream error", http.StatusBadGateway)

			return
		}

		defer resp.Body.Close()

		stripHopByHopHeaders(resp.Header)

		if p.cache != nil && p.cache.ShouldConsider(req) {
			// 需要写入缓存的响应整体读入内存
			body, _ := io.ReadAll(resp.Body)
			body = p.applyBufferedResponseFault(req.Context(), req, resp, body, requestID)
			verdict, scanErr := p.scanBufferedResponse(req.Context(), req, resp, body)
			if p.shouldBlock(verdict, scanErr) {
				writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
				return
			}

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}

			w.WriteHeader(resp.StatusCode)
			n, _ := w.Write(body)
			p.cache.SaveContext(req.Context(), req.URL, resp, body)

			p.logRequest("HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s (cached)", req.Method, req.URL.String(), resp.StatusCode, n, time.Since(start))
			p.publishTrafficCompleted(requestID, req, resp.StatusCode, n, time.Since(start), false, resp.Header)

			return
		}

		// 不入缓存的响应直接流式转发
		verdict, scanErr = p.prepareResponseForScan(req.Context(), req, resp)
		if p.shouldBlock(verdict, scanErr) {
			writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
			return
		}
		p.wrapStreamingResponseFault(req.Context(), req, resp, requestID)

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(resp.StatusCode)
		n, _ := io.Copy(w, resp.Body)

		dur := time.Since(start)

		p.logRequest("HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s", req.Method, req.URL.String(), resp.StatusCode, n, dur)
		p.publishTrafficCompleted(requestID, req, resp.StatusCode, int(n), dur, false, resp.Header)
	})

	h2s.ServeConn(clientTLS, &http2.ServeConnOpts{Handler: handler})
}
