package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
)

// relayWebSocket 在客户端与上游之间双向转发字节，实现 ws/wss 透明隧道。
// clientReader / upstreamReader 是解析握手时使用的带缓冲读取器，
// 隧道从它们继续读取；任一方向结束后同时关闭两端连接。
func relayWebSocket(client net.Conn, clientReader io.Reader, upstream net.Conn, upstreamReader io.Reader) {
	go func() {
		defer client.Close()
		defer upstream.Close()

		_, _ = io.Copy(upstream, clientReader)
	}()

	go func() {
		defer client.Close()
		defer upstream.Close()

		_, _ = io.Copy(client, upstreamReader)
	}()
}

// stripWebSocketCompression 去掉 permessage-deflate 扩展。
// 代理只做透明转发、不参与压缩协商，若保留该扩展会让客户端误以为
// 消息被压缩，导致收发双方对帧内容的理解不一致。
func stripWebSocketCompression(h http.Header) {
	for _, value := range h.Values("Sec-WebSocket-Extensions") {
		if strings.Contains(strings.ToLower(value), "permessage-deflate") {
			h.Del("Sec-WebSocket-Extensions")
			return
		}
	}
}
