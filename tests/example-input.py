import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
password = "admin123"
api_key = "sk-1234567890abcdef"

def get_db():
    conn = sqlite3.connect('users.db')
    return conn

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "success", "user": user})
    else:
        return jsonify({"status": "failed"})

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    filename = file.filename
    file.save(os.path.join('/tmp/uploads', filename))
    return jsonify({"status": "uploaded", "filename": filename})

def process_data(items):
    result = []
    for item in items:
        for subitem in item['children']:
            for detail in subitem['details']:
                result.append(detail['value'] * 2)
    return result

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
