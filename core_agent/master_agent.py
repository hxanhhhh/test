import requests

class MasterSecurityAgent:
    def __init__(self, ollama_model="qwen2.5-coder:3b"):
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"

    def ask_ollama(self, prompt: str) -> str:
        payload = {"model": self.ollama_model, "prompt": prompt, "stream": False}
        try:
            res = requests.post(self.ollama_url, json=payload, timeout=60)
            if res.status_code == 200:
                return res.json().get("response", "")
            return "Lỗi gọi Ollama"
        except Exception as e:
            return f"Lỗi kết nối Ollama: {str(e)}"
