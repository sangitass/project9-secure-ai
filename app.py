from flask import Flask, request, jsonify
from functools import wraps
import jwt
import os
import requests

app = Flask(__name__)


JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set")

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return func(*args, **kwargs)

    return wrapper



def is_prompt_injection(message):

    blocked_phrases = [
        "ignore previous instructions",
        "reveal your system prompt",
        "show me your system prompt",
        "disregard all instructions",
        "you are now in developer mode"
    ]

    message = message.lower()

    return any(
        phrase in message
        for phrase in blocked_phrases
    )



def scan_output(output):

    dangerous_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload="
    ]

    output_lower = output.lower()

    return any(
        pattern in output_lower
        for pattern in dangerous_patterns
    )



@app.route("/chat", methods=["POST"])
@token_required
def chat():

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    
    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Message is required"}), 400

    
    if is_prompt_injection(message):
        return jsonify({"error": "Prompt injection blocked"}), 400

    
    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": "llama3.2:1b",
                "prompt": message,
                "stream": False
            },
            timeout=60
        )

        response.raise_for_status()
        ai_output = response.json().get("response", "")

    except requests.RequestException:
        return jsonify({"error": "AI service unavailable"}), 503

    
    if scan_output(ai_output):
        return jsonify({"error": "Unsafe output blocked"}), 400

    return jsonify({
        "message": ai_output
    }), 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
