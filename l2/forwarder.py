#!/usr/bin/env python3
"""L2 harness 本地转发层：让 harness（不走代理的 MoonBit HTTP 客户端）经
HTTP 代理访问被墙平台端点。

用法：
  python3 l2/forwarder.py \
    --listen 127.0.0.1:9877 \
    --proxy  http://127.0.0.1:7890 \
    --map /api=https://discord.com/api \
    --map /token=https://oauth2.googleapis.com/token

匹配规则：最长前缀优先；转发保留 method/headers/body，路径余部拼接到上游。
"""

import argparse
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}

MAPS = []  # [(local_prefix, upstream_base)] 最长前缀优先


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 安静模式
        sys.stderr.write("[forwarder] %s\n" % (fmt % args))

    def _do(self):
        path = self.path
        target = None
        for prefix, upstream in MAPS:
            if path == prefix or path.startswith(prefix if prefix.endswith("/") else prefix + "/") or path.startswith(prefix):
                rest = path[len(prefix):]
                target = upstream + rest
                break
        if target is None:
            self._send(404, b'{"error":"no mapping for path"}')
            return
        body = None
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            # 读掉 chunked 编码请求体（harness 的 MoonBit HTTP 客户端用此形态），
            # 解码后以普通 body 转发（urllib 自动重设 Content-Length）。
            chunks = []
            while True:
                size_line = self.rfile.readline().strip()
                size = int(size_line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()  # 结束块的 CRLF
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()  # 每块后的 CRLF
            body = b"".join(chunks)
        else:
            length = self.headers.get("Content-Length")
            if length:
                body = self.rfile.read(int(length))
        headers = {}
        for k, v in self.headers.items():
            if k.lower() not in HOP_HEADERS:
                headers[k] = v
        # 强制 identity：上游不做压缩，转发层与 harness 都无需解压
        # （此前剥掉 Content-Encoding 头但透传了压缩体，harness 文本解码失败）。
        headers["Accept-Encoding"] = "identity"
        req = urllib.request.Request(target, data=body, headers=headers, method=self.command)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
        try:
            with opener.open(req, timeout=30) as resp:
                data = resp.read()
                self._send(resp.status, data, dict(resp.headers))
        except urllib.error.HTTPError as e:
            data = e.read()
            self._send(e.code, data, dict(e.headers or {}))
        except Exception as e:  # noqa: BLE001
            sys.stderr.write("[forwarder] upstream error: %r\n" % (e,))
            self._send(502, ('{"error":"forwarder upstream failed: %s"}' % e).encode())

    def _send(self, status, data, headers=None):
        self.send_response(status)
        headers = headers or {}
        for k, v in headers.items():
            if k.lower() not in HOP_HEADERS:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _do


def main():
    global PROXY
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:9877")
    ap.add_argument("--proxy", default="http://127.0.0.1:7890")
    ap.add_argument("--map", action="append", required=True, help="/prefix=https://upstream/base")
    args = ap.parse_args()
    PROXY = args.proxy
    for m in args.map:
        local, upstream = m.split("=", 1)
        MAPS.append((local, upstream))
    MAPS.sort(key=lambda kv: -len(kv[0]))
    host, port = args.listen.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    sys.stderr.write("[forwarder] listening on %s via %s\n" % (args.listen, args.proxy))
    srv.serve_forever()


if __name__ == "__main__":
    main()
