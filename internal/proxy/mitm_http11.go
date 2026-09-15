package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"mitm-proxy/internal/access"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/upstream"
)

// mitmHTTPS11 处理 ALPN 协商结果为 HTTP/1.1 的 HTTPS 流量。
// 它在与客户端建立 TLS 之后，逐个读取明文请求并转发到上游，
// 从而让 HTTPS 内容也能被审计与拦截。
func (p *Proxy) mitmHTTPS11(clientTLS net.Conn, host, proxyUser, remoteAddr string) {
	reader := bufio.NewReader(clientTLS)

	for {
		req, err := http.ReadRequest(reader)

		if err != nil {
			if err != io.EOF {
				log.Printf("ReadRequest error for host %s: %v", host, err)
			}
			clientTLS.Close()

			return
		}

		// 极少数客户端会在 HTTP/1.1 通道上发送 HTTP/2 前导帧，忽略即可
		if req.Method == "PRI" && req.URL.Path == "*" && req.ProtoMajor == 2 {
			p.logVerbose("Got HTTP/2 PRI preface on HTTP/1.1 path for %s; ignoring", host)

			continue
		}

		// wss:// 升级：握手成功后转为透明隧道
		if isWebSocketRequest(req) {
			p.logVerbose("Detected wss:// WebSocket upgrade to %s", host)
			p.handleWebSocketHTTPS11(clientTLS, reader, req, host, proxyUser, remoteAddr)

			return
		}

		start := time.Now()
		requestID := requestID(start)
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
			blocked := accessBlockedResponse(p.cfg(), accessDecision)
			_ = blocked.Write(clientTLS)
			continue
		}

		stripHopByHopHeaders(req.Header)
		p.publishTrafficStarted(requestID, req, "https/1.1")
		effectiveCfg := p.effectiveConfigForRequest(req)

		// 故障注入命中时直接本地构造响应
		if result := p.applyRequestFault(req.Context(), req, requestID); result.Handled {
			if result.Rule.Action == "drop" {
				p.publishBlocked(requestID, req, result.Rule.ID, "dropped by fault injection")
			}
			out := syntheticHTTPResponse(result)
			_ = out.Write(clientTLS)
			p.publishTrafficCompleted(requestID, req, out.StatusCode, len(result.Body), time.Since(start), false, out.Header)
			continue
		}

		// 黑白名单（端口/域名/IP）拦截
		if decision := p.checkPolicyWithConfig(effectiveCfg, req.URL.Host); decision.Blocked {
			p.publishBlocked(requestID, req, decision.RuleID, decision.Reason)
			blocked := threatBlockedResponse(threatsFromPolicy(decision))
			_ = blocked.Write(clientTLS)
			continue
		}

		// 请求方向的内容安全扫描
		verdict, scanErr := p.scanRequest(req.Context(), req)
		if p.shouldBlock(verdict, scanErr) {
			blocked := threatBlockedResponse(verdict)
			_ = blocked.Write(clientTLS)
			continue
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
					blocked := threatBlockedResponse(verdict)
					_ = blocked.Write(clientTLS)
					continue
				}
				body := cr.Body

				// 直接把缓存响应写回 TLS 连接
				hdr := make(http.Header)

				for k, vv := range cachedResp.Header {
					for _, v := range vv {
						hdr.Add(k, v)
					}
				}

				// 标记该响应由本地缓存提供
				hdr.Set("Via", p.cfg().ProxyName)

				// 附加一个由代理名派生的 UID 响应头，值为缓存文件哈希
				uidHeader := p.makeCustomHeader("uid")
				hdr.Set(uidHeader, hashHex)

				cached := &http.Response{StatusCode: cachedResp.StatusCode, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: hdr, Body: io.NopCloser(bytes.NewReader(body))}
				_ = cached.Write(clientTLS)

				p.logRequest("CACHE HIT HTTPS/1.1 %s %s -> status=%d, dur=%s", req.Method, req.URL.String(), cr.Status, time.Since(start))
				p.publishTrafficCompleted(requestID, req, cachedResp.StatusCode, len(body), time.Since(start), true, cachedResp.Header)

				continue
			}
			p.publish(events.TopicCacheMiss, map[string]any{"url": req.URL.String()}, requestID)
		}

		resp, err := p.httpClientForConfig(effectiveCfg).Do(req)

		if err != nil {
			log.Printf("upstream HTTPS/1.1 error: %v", err)
			clientTLS.Close()

			return
		}

		if p.cache != nil && p.cache.ShouldConsider(req) {
			// 需要写入缓存的响应整体读入内存后再回写
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			stripHopByHopHeaders(resp.Header)
			body = p.applyBufferedResponseFault(req.Context(), req, resp, body, requestID)

			verdict, scanErr := p.scanBufferedResponse(req.Context(), req, resp, body)
			if p.shouldBlock(verdict, scanErr) {
				blocked := threatBlockedResponse(verdict)
				_ = blocked.Write(clientTLS)
				continue
			}

			// 构造回写给客户端的响应
			out := &http.Response{StatusCode: resp.StatusCode, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: resp.Header.Clone(), Body: io.NopCloser(bytes.NewReader(body))}

			if err := out.Write(clientTLS); err != nil {
				log.Printf("write to client error: %v", err)
				clientTLS.Close()

				return
			}

			p.cache.SaveContext(req.Context(), req.URL, resp, body)

			p.logRequest("HTTPS/1.1 %s %s -> status=%d, dur=%s (cached)", req.Method, req.URL.String(), resp.StatusCode, time.Since(start))
			p.publishTrafficCompleted(requestID, req, resp.StatusCode, len(body), time.Since(start), false, resp.Header)
		} else {
			p.logRequest("HTTPS/1.1 %s %s -> status=%d, dur=%s", req.Method, req.URL.String(), resp.StatusCode, time.Since(start))

			stripHopByHopHeaders(resp.Header)
			verdict, scanErr = p.prepareResponseForScan(req.Context(), req, resp)
			if p.shouldBlock(verdict, scanErr) {
				resp.Body.Close()
				blocked := threatBlockedResponse(verdict)
				_ = blocked.Write(clientTLS)
				continue
			}
			p.wrapStreamingResponseFault(req.Context(), req, resp, requestID)
			err = resp.Write(clientTLS)
			resp.Body.Close()

			if err != nil {
				log.Printf("write to client error: %v", err)

				clientTLS.Close()

				return
			}
			p.publishTrafficCompleted(requestID, req, resp.StatusCode, -1, time.Since(start), false, resp.Header)
		}
	}
}

// handleWebSocketHTTPS11 在已建立的 TLS 中间人通道上转发 wss:// 升级。
// 代理对上游单独发起一次 TLS 握手，握手成功后只做透明字节转发。
func (p *Proxy) handleWebSocketHTTPS11(clientTLS net.Conn, clientReader *bufio.Reader, req *http.Request, host, proxyUser, remoteAddr string) {
	targetHost := req.URL.Host

	if targetHost == "" {
		if req.Host != "" {
			targetHost = req.Host
		} else {
			targetHost = host
		}
	}

	if !strings.Contains(targetHost, ":") {
		targetHost = net.JoinHostPort(targetHost, "443")
	}
	req.RemoteAddr = remoteAddr
	if proxyUser != "" {
		req = req.WithContext(access.WithUsername(req.Context(), proxyUser))
	}
	accessDecision := p.accessController().AuthorizeKnownUser(req.Context(), proxyUser, remoteAddr, req.Method, "https://"+targetHost+req.URL.RequestURI())
	if !accessDecision.Allowed {
		p.publishAccessDenied(req, accessDecision)
		blocked := accessBlockedResponse(p.cfg(), accessDecision)
		_ = blocked.Write(clientTLS)
		clientTLS.Close()
		return
	}
	// 认证信息只用于代理自身，不能透传给上游
	req.Header.Del("Proxy-Authorization")
	stripWebSocketCompression(req.Header)

	rawUpstream, err := upstream.DialContext(req.Context(), p.cfg(), targetHost)

	if err != nil {
		log.Printf("wss upstream dial error: %v", err)

		clientTLS.Close()

		return
	}

	// 上游 TLS 需要按目标域名做 SNI 与证书校验
	serverName := targetHost

	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		serverName = h
	}

	upstreamTLS := tls.Client(rawUpstream, &tls.Config{ServerName: serverName})

	if err := upstreamTLS.Handshake(); err != nil {
		log.Printf("wss upstream TLS handshake error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	if err := req.Write(upstreamTLS); err != nil {
		log.Printf("wss write request to upstream error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	upstreamReader := bufio.NewReader(upstreamTLS)
	resp, err := http.ReadResponse(upstreamReader, req)

	if err != nil {
		log.Printf("wss read response from upstream error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	// 101 响应体通常为空，但仍要关闭以免连接泄漏
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("wss upgrade failed: status=%d", resp.StatusCode)

		_ = resp.Write(clientTLS)
		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	if err := resp.Write(clientTLS); err != nil {
		log.Printf("wss write response to client error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	p.logVerbose("wss tunnel established %s <-> %s", clientTLS.RemoteAddr(), targetHost)
	p.publishTunnelOpened(targetHost, "wss", clientTLS.RemoteAddr().String())
	// 把两侧已缓冲的 reader 一并交给隧道
	relayWebSocket(clientTLS, clientReader, upstreamTLS, upstreamReader)
}
