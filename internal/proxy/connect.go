package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"mitm-proxy/internal/access"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/upstream"
)

// tunnelTCPWithConfig 在客户端与目标之间做纯粹的 TCP 字节转发，
// 不解密流量。用于被排除的域名、非 443 端口，以及关闭 MITM 的场景。
func tunnelTCPWithConfig(ctx context.Context, clientConn net.Conn, target string, p *Proxy, cfg *cfgpkg.Config) {
	upstream, err := upstream.DialContext(ctx, cfg, target)

	if err != nil {
		log.Printf("CONNECT tunnel dial error to %s: %v", target, err)

		clientConn.Close()

		return
	}

	p.logVerbose("CONNECT tunnel %s <-> %s", clientConn.RemoteAddr(), target)

	go func() {
		defer clientConn.Close()
		defer upstream.Close()

		io.Copy(upstream, clientConn)
	}()

	go func() {
		defer clientConn.Close()
		defer upstream.Close()

		io.Copy(clientConn, upstream)
	}()
}

// handleConnect 处理 CONNECT 请求，并决定走明文隧道还是 HTTPS 中间人解密。
// 判断顺序：访问控制 → 黑白名单 → 排除域名 → 非 443 端口 → MITM 开关。
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host

	// CONNECT 请求可能不带端口，默认按 443 处理
	if !strings.Contains(hostPort, ":") {
		hostPort = net.JoinHostPort(hostPort, "443")
	}

	host, port, err := net.SplitHostPort(hostPort)

	if err != nil {
		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)

		return
	}

	accessDecision := p.accessController().AuthorizeRequest(r, hostPort)
	if !accessDecision.Allowed {
		p.publishAccessDenied(r, accessDecision)
		access.WriteDenied(w, p.cfg(), accessDecision)
		return
	}
	proxyUser := accessDecision.Username
	effectiveCfg := p.effectiveConfigForHost(r.Context(), host)

	if decision := p.checkPolicyWithConfig(effectiveCfg, hostPort); decision.Blocked {
		p.publish(events.TopicTrafficBlocked, map[string]any{
			"method":     r.Method,
			"target":     hostPort,
			"host":       host,
			"rule_id":    decision.RuleID,
			"reason":     decision.Reason,
			"remote_ip":  remoteIP(r.RemoteAddr),
			"proxy_user": proxyUser,
		}, "")
		http.Error(w, decision.Reason, effectiveCfg.BlockResponseStatus)
		return
	}

	// 接管底层连接后，代理需要自己写回响应，不能再依赖 net/http
	hj, ok := w.(http.Hijacker)

	if !ok {
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)

		return
	}

	clientConn, buf, err := hj.Hijack()

	if err != nil {
		log.Printf("hijack error: %v", err)

		return
	}
	_ = buf

	// 隧道使用独立于请求生命周期的上下文拨号：
	// 数据搬运在 handleConnect 返回之后仍会继续。
	tunnelCtx := context.Background()

	// 先告知客户端隧道已建立，之后这条连接上跑的就是原始字节流
	if _, err = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("write 200 Connection Established failed: %v", err)

		clientConn.Close()

		return
	}

	// 命中排除名单的域名不解密，直接放行原始 TLS 流量
	if effectiveCfg.IsDomainExcluded(host) {
		p.logVerbose("Domain %s is excluded, using plain tunnel", host)
		p.publishTunnelOpened(hostPort, "connect", r.RemoteAddr, proxyUser)

		go tunnelTCPWithConfig(tunnelCtx, clientConn, hostPort, p, effectiveCfg)

		return
	}

	// 只对标准 HTTPS 端口做中间人解密，其它端口无法假定是 TLS 服务
	if port != "443" {
		p.publishTunnelOpened(hostPort, "connect", r.RemoteAddr, proxyUser)
		go tunnelTCPWithConfig(tunnelCtx, clientConn, hostPort, p, effectiveCfg)

		return
	}

	if !effectiveCfg.EnableMITM {
		p.logVerbose("MITM disabled, using plain tunnel for %s", hostPort)
		p.publishTunnelOpened(hostPort, "connect", r.RemoteAddr, proxyUser)

		go tunnelTCPWithConfig(tunnelCtx, clientConn, hostPort, p, effectiveCfg)

		return
	}

	// 用本地 CA 现场为该域名签发叶子证书，这是解密 HTTPS 的前提
	cert, err := p.getCertForHost(host)

	if err != nil {
		log.Printf("getCertForHost(%q) error: %v", host, err)

		clientConn.Close()

		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   effectiveCfg.GetTLSVersion(),
		NextProtos:   effectiveCfg.TLSNextProtos,
	})

	// 与客户端完成 TLS 握手；客户端信任本地 CA 时即可继续
	if err := tlsConn.Handshake(); err != nil {
		if errors.Is(err, io.EOF) {
			p.logVerbose("TLS handshake aborted by client for %s from %s: %v", hostPort, r.RemoteAddr, err)
		} else {
			log.Printf("TLS handshake with client failed for %s from %s: %v", hostPort, r.RemoteAddr, err)
		}

		tlsConn.Close()

		return
	}

	state := tlsConn.ConnectionState()

	p.logVerbose("Established TLS MITM for %s:%s, ALPN=%q", host, port, state.NegotiatedProtocol)

	// 按 ALPN 协商结果选择 HTTP/2 或 HTTP/1.1 处理路径
	switch state.NegotiatedProtocol {
	case "h2":
		p.mitmHTTPS2(tlsConn, host, proxyUser, r.RemoteAddr)
	default:
		p.mitmHTTPS11(tlsConn, host, proxyUser, r.RemoteAddr)
	}
}
