#!/usr/bin/env python3
"""Deterministic stdlib-only test endpoint. Never logs requests or their content."""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def json_response(self, status, data):
        body = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self.json_response(200, {"status": "ok"})
        elif path == "/v1/models":
            self.json_response(200, {"object": "list", "data": [
                {"id": "stub", "object": "model", "created": 0, "owned_by": "trcs"}]})
        else:
            self.json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/v1/chat/completions":
            self.close_connection = True
            self.json_response(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 33554432:
                raise ValueError("length")
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError("object required")
        except (ValueError, TypeError):
            self.close_connection = True
            self.json_response(400, {"error": "invalid request"})
            return
        usage = {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
        base = {"id": "chatcmpl-stub", "created": 0, "model": "stub"}
        if not request.get("stream", False):
            self.json_response(200, dict(base, object="chat.completion", choices=[{
                "index": 0, "message": {"role": "assistant", "content": "Hello world"},
                "finish_reason": "stop"}], usage=usage))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        chunks = [
            {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hello"}, "finish_reason": None}]},
            {"choices": [{"index": 0, "delta": {"content": " world"}, "finish_reason": None}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            {"choices": [], "usage": usage},
        ]
        try:
            for chunk in chunks:
                payload = dict(base, object="chat.completion.chunk", **chunk)
                self.wfile.write(("data: " + json.dumps(payload) + "\n\n").encode())
                self.wfile.flush()
                time.sleep(0.2)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class Server(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        # Avoid traceback dumps that might expose request content.
        pass


if __name__ == "__main__":
    Server(("127.0.0.1", 8000), Handler).serve_forever()
