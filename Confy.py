from flask import Flask, request, jsonify
import sqlite3
import time

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT UNIQUE,
                        ip TEXT,
                        timestamp INTEGER
                    )''')
    conn.commit()
    conn.close()

@app.route('/generate_key', methods=['POST'])
def generate_key():
    data = request.json
    key = data.get('key')
    ip = request.remote_addr  # Obtém IP externo do cliente
    
    timestamp = int(time.time())
    
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO keys (key, ip, timestamp) VALUES (?, ?, ?)", (key, ip, timestamp))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Chave registrada com sucesso", "ip": ip}), 200



@app.route('/get_ip', methods=['GET'])
def get_ip():
    key = request.args.get('key')
    
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM keys WHERE key = ?", (key,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({"ip": result[0]}), 200
    else:
        return jsonify({"error": "Chave não encontrada"}), 404

@app.route('/cleanup', methods=['DELETE'])
def cleanup():
    expiry_time = int(time.time()) - 600  # Remove chaves mais antigas que 10 minutos
    
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM keys WHERE timestamp < ?", (expiry_time,))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Chaves expiradas removidas"}), 200

if __name__ == '__main__':
    init_db()
    app.run(host='10.10.1.4', port=5000, debug=True)
