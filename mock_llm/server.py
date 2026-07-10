import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class MockLLMHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        path = self.path
        response_data = {}
        status_code = 200
        
        try:
            if "generateContent" in path:
                # Gemini format
                req = json.loads(post_data.decode('utf-8'))
                prompt = req.get("contents", [{}])[0].get("parts", [{}])[0].get("text", "")
                
                response_data = {
                    "candidates": [{
                        "content": {
                            "parts": [{"text": f"Mock Response: Gemini parsed your prompt: '{prompt}'"}],
                            "role": "model"
                        },
                        "finishReason": "STOP"
                    }]
                }
            elif "messages" in path:
                # Claude format
                req = json.loads(post_data.decode('utf-8'))
                prompt = req.get("messages", [{}])[0].get("content", "")
                
                response_data = {
                    "id": "mock_msg_claude1234",
                    "role": "assistant",
                    "content": [{"type": "text", "text": f"Mock Response: Claude parsed your prompt: '{prompt}'"}],
                    "model": req.get("model", "claude-mock"),
                    "stop_reason": "end_turn",
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 15
                    }
                }
            elif "execute" in path:
                # Agent tool execution
                req = json.loads(post_data.decode('utf-8'))
                tool = req.get("tool", "unknown_tool")
                
                response_data = {
                    "status": "SUCCESS",
                    "result": f"Mock execution of tool '{tool}' succeeded with arguments: {json.dumps(req.get('args', {}))}"
                }
            else:
                # Standard OpenAI format
                req = json.loads(post_data.decode('utf-8'))
                prompt = req.get("messages", [{}])[-1].get("content", "")
                
                response_data = {
                    "id": "mock_chatcmpl_openai1234",
                    "object": "chat.completion",
                    "created": 1677652288,
                    "model": req.get("model", "gpt-mock"),
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"Mock Response: OpenAI parsed your prompt: '{prompt}'"
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 12,
                        "completion_tokens": 18,
                        "total_tokens": 30
                    }
                }
        except Exception as e:
            status_code = 400
            response_data = {"error": f"Failed to parse mock request: {str(e)}"}
            print(f"[MockLLM Error] {e}")

        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

from socketserver import ThreadingMixIn

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def run(port=8081):
    server_address = ('', port)
    httpd = ThreadingHTTPServer(server_address, MockLLMHandler)
    print(f"[MockLLM] Running Mock LLM Server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
