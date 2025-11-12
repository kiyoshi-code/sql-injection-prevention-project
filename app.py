from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
from datetime import datetime
import re
import bcrypt

app = Flask(__name__)
CORS(app)

DB_FILE = 'sql_injection_demo.db'

# HTML Template (embedded in Python)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Prevention - Security Testing Platform</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f1e;
            min-height: 100vh;
            padding: 20px;
            color: #e0e0e0;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            color: white;
            margin-bottom: 40px;
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: #ffffff;
        }
        
        header p {
            font-size: 1em;
            opacity: 0.8;
            font-weight: 300;
            color: #a0a0c0;
        }
        
        .section {
            background: #1a1a2e;
            border-radius: 8px;
            padding: 28px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            border: 1px solid #2a2a44;
        }
        
        .section-title {
            font-size: 1.4em;
            color: #ffffff;
            margin-bottom: 20px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }
        
        .input-section {
            background: #252540;
            padding: 24px;
            border-radius: 6px;
            margin-bottom: 20px;
            border-left: 4px solid #4a9eff;
        }
        
        .input-section h3 {
            font-size: 1.1em;
            color: #ffffff;
            margin-bottom: 18px;
            font-weight: 600;
        }
        
        .input-group {
            margin-bottom: 18px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #b0b0d0;
            font-size: 0.95em;
        }
        
        .input-group textarea {
            width: 100%;
            padding: 14px;
            border: 2px solid #3a3a5a;
            border-radius: 6px;
            font-size: 0.95em;
            font-family: 'Courier New', monospace;
            resize: vertical;
            min-height: 120px;
            transition: all 0.3s;
            background: #1a1a2e;
            color: #e0e0e0;
        }
        
        .input-group textarea:focus {
            outline: none;
            border-color: #4a9eff;
            box-shadow: 0 0 0 3px rgba(74, 158, 255, 0.15);
        }
        
        .input-group textarea::placeholder {
            color: #5a5a7a;
        }
        
        .button-group {
            display: flex;
            gap: 12px;
            margin-top: 20px;
        }
        
        .btn {
            padding: 12px 28px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s;
            font-size: 0.95em;
        }
        
        .btn-analyze {
            background: #4a9eff;
            color: white;
            flex: 1;
        }
        
        .btn-analyze:hover {
            background: #3a8eef;
            box-shadow: 0 4px 12px rgba(74, 158, 255, 0.3);
            transform: translateY(-2px);
        }
        
        .btn-reset {
            background: #3a3a5a;
            color: white;
        }
        
        .btn-reset:hover {
            background: #4a4a6a;
        }
        
        .results-container {
            margin-top: 30px;
        }
        
        .results-title {
            font-weight: 600;
            margin-bottom: 18px;
            color: #ffffff;
            font-size: 1.05em;
        }
        
        .results-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .result-box {
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            border: 1px solid #2a2a44;
        }
        
        .result-header {
            padding: 14px 18px;
            font-weight: 600;
            color: white;
            font-size: 0.95em;
        }
        
        .result-header.vulnerable {
            background: #ef4444;
        }
        
        .result-header.secure {
            background: #10b981;
        }
        
        .result-content {
            background: #1a1a2e;
            padding: 18px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #d0d0d0;
            max-height: 450px;
            overflow-y: auto;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .result-content::-webkit-scrollbar {
            width: 8px;
        }
        
        .result-content::-webkit-scrollbar-track {
            background: #252540;
        }
        
        .result-content::-webkit-scrollbar-thumb {
            background: #3a3a5a;
            border-radius: 4px;
        }
        
        .result-content::-webkit-scrollbar-thumb:hover {
            background: #4a4a6a;
        }
        
        .result-query {
            background: rgba(251, 191, 36, 0.1);
            border-left: 3px solid #fbbf24;
            padding: 10px;
            margin: 8px 0;
            border-radius: 3px;
            font-size: 0.85em;
            color: #fcd34d;
        }
        
        .result-error {
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid #ef4444;
            color: #fca5a5;
            padding: 10px;
            margin: 8px 0;
            border-radius: 3px;
            font-size: 0.85em;
        }
        
        .result-success {
            background: rgba(16, 185, 129, 0.1);
            border-left: 3px solid #10b981;
            color: #6ee7b7;
            padding: 10px;
            margin: 8px 0;
            border-radius: 3px;
            font-size: 0.85em;
        }
        
        .result-table {
            width: 100%;
            border-collapse: collapse;
            margin: 8px 0;
            font-size: 0.8em;
            background: #252540;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .result-table th,
        .result-table td {
            border: 1px solid #3a3a5a;
            padding: 8px;
            text-align: left;
        }
        
        .result-table th {
            background: #2a2a44;
            font-weight: 600;
            color: #ffffff;
        }
        
        .result-table td {
            color: #d0d0d0;
        }
        
        .info-box {
            background: rgba(74, 158, 255, 0.1);
            border-left: 3px solid #4a9eff;
            padding: 10px;
            margin: 8px 0;
            border-radius: 3px;
            font-size: 0.85em;
            color: #93c5fd;
        }
        
        .placeholder {
            color: #5a5a7a;
            text-align: center;
            padding: 30px;
            font-style: italic;
            font-size: 0.9em;
        }
        
        .loading {
            color: #4a9eff;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 30px;
        }
        
        .stat-card {
            background: #252540;
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #3a3a5a;
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: #4a9eff;
        }
        
        .stat-card h3 {
            font-size: 2em;
            margin-bottom: 5px;
            font-weight: 600;
            color: #4a9eff;
        }
        
        .stat-card p {
            opacity: 0.8;
            font-size: 0.85em;
            font-weight: 300;
            color: #b0b0d0;
        }
        
        .connection-status {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 6px;
            font-size: 0.85em;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
            z-index: 1000;
            display: none;
            border: 1px solid;
        }
        
        .connection-status.error {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border-color: #ef4444;
            display: block;
        }
        
        .connection-status.success {
            background: rgba(16, 185, 129, 0.2);
            color: #6ee7b7;
            border-color: #10b981;
        }
        
        @media (max-width: 768px) {
            .results-grid {
                grid-template-columns: 1fr;
            }
            
            .stats {
                grid-template-columns: 1fr;
            }
            
            header h1 {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SQL Injection Prevention</h1>
            <p>Security Testing Platform</p>
        </header>
        
        <div class="section">
            <h2 class="section-title">SQL Query Analysis</h2>
            
            <div class="input-section">
                <h3>Enter SQL Query</h3>
                <div class="input-group">
                    <label>SQL Query:</label>
                    <textarea id="sqlQuery" placeholder="Enter your SQL query here...

Try these examples:
  • SELECT * FROM users WHERE username='admin' --'
  • SELECT * FROM products WHERE product_id=1 OR 1=1
  • SELECT * FROM users WHERE user_id=1; DROP TABLE users; --"></textarea>
                </div>
                
                <div class="button-group">
                    <button class="btn btn-analyze" onclick="analyzeQuery()">Analyze</button>
                    <button class="btn btn-reset" onclick="resetAnalysis()">Clear</button>
                </div>
            </div>
            
            <div class="results-container">
                <div class="results-title">Analysis Results</div>
                <div class="results-grid">
                    <div class="result-box">
                        <div class="result-header vulnerable">Vulnerable Implementation</div>
                        <div class="result-content" id="vulnOutput">
                            <div class="placeholder">Enter a SQL query and click Analyze to see results</div>
                        </div>
                    </div>
                    
                    <div class="result-box">
                        <div class="result-header secure">Secure Implementation</div>
                        <div class="result-content" id="secureOutput">
                            <div class="placeholder">Enter a SQL query and click Analyze to see results</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3 id="totalAttempts">0</h3>
                    <p>Total Tests Run</p>
                </div>
                <div class="stat-card">
                    <h3 id="vulnBreaches">0</h3>
                    <p>Vulnerabilities Detected</p>
                </div>
                <div class="stat-card">
                    <h3 id="secureBlocks">0</h3>
                    <p>Attacks Prevented</p>
                </div>
            </div>
        </div>
    </div>
    
    <div id="connectionStatus" class="connection-status"></div>
    
    <script>
        let stats = {
            totalAttempts: 0,
            vulnBreaches: 0,
            secureBlocks: 0
        };
        
        // No need for API_URL since we're on the same server
        const API_URL = '';
        
        window.addEventListener('load', checkBackendConnection);
        
        async function checkBackendConnection() {
            try {
                const response = await fetch(`${API_URL}/api/reset-db`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                
                if (response.ok) {
                    showConnectionStatus('Backend connected successfully', 'success');
                    setTimeout(() => hideConnectionStatus(), 3000);
                }
            } catch (error) {
                showConnectionStatus('Backend connection error', 'error');
            }
        }
        
        function showConnectionStatus(message, type) {
            const status = document.getElementById('connectionStatus');
            status.textContent = message;
            status.className = `connection-status ${type}`;
            status.style.display = 'block';
        }
        
        function hideConnectionStatus() {
            const status = document.getElementById('connectionStatus');
            status.style.display = 'none';
        }
        
        function detectQueryType(query) {
            const trimmed = query.trim().toUpperCase();
            
            if (trimmed.startsWith('SELECT')) return 'select';
            if (trimmed.startsWith('INSERT')) return 'insert';
            if (trimmed.startsWith('UPDATE')) return 'update';
            if (trimmed.startsWith('DELETE')) return 'delete';
            if (trimmed.startsWith('DROP')) return 'drop';
            
            return null;
        }
        
        async function analyzeQuery() {
            const query = document.getElementById('sqlQuery').value.trim();
            
            if (!query) {
                alert('Please enter a SQL query');
                return;
            }
            
            const queryType = detectQueryType(query);
            if (!queryType) {
                alert('Unable to identify query type. Please enter a valid SQL query.');
                return;
            }
            
            document.getElementById('vulnOutput').innerHTML = '<div class="loading">Analyzing...</div>';
            document.getElementById('secureOutput').innerHTML = '<div class="loading">Analyzing...</div>';
            
            stats.totalAttempts++;
            updateStats();
            
            try {
                const [vulnResponse, secureResponse] = await Promise.all([
                    fetch(`${API_URL}/api/vulnerable/analyze`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ query, type: queryType })
                    }),
                    fetch(`${API_URL}/api/secure/analyze`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ query, type: queryType })
                    })
                ]);
                
                const vulnResult = await vulnResponse.json();
                const secureResult = await secureResponse.json();
                
                if (vulnResult.status === 'success' && vulnResult.is_vulnerable) {
                    stats.vulnBreaches++;
                }
                if (secureResult.status === 'error' || (secureResult.status === 'success' && secureResult.attack_blocked)) {
                    stats.secureBlocks++;
                }
                updateStats();
                
                displayResult(vulnResult, 'vulnerable');
                displayResult(secureResult, 'secure');
            } catch (error) {
                const errorMsg = `CONNECTION ERROR

Cannot connect to backend server.

Error: ${error.message}`;
                
                document.getElementById('vulnOutput').innerHTML = `<div class="result-error">${errorMsg}</div>`;
                document.getElementById('secureOutput').innerHTML = `<div class="result-error">${errorMsg}</div>`;
                
                showConnectionStatus('Backend connection error', 'error');
            }
        }
        
        function displayResult(result, type) {
            const outputId = type === 'vulnerable' ? 'vulnOutput' : 'secureOutput';
            let html = '';
            
            if (result.status === 'error') {
                html = `<div class="result-error">Error\n\n${result.message || result.error}</div>`;
            } else {
                if (result.query) {
                    html += `<div class="result-query">Query:\n${result.query}</div>`;
                }
                
                if (result.parameters) {
                    html += `<div class="result-query">Parameters:\n[${result.parameters.join(', ')}]</div>`;
                }
                
                if (result.protection) {
                    html += `<div class="result-success">Protection:\n${result.protection}</div>`;
                }
                
                if (result.message) {
                    html += `<div class="result-success">${result.message}</div>`;
                }
                
                if (result.results && result.results.length > 0) {
                    html += '<table class="result-table"><tr>';
                    Object.keys(result.results[0]).forEach(key => {
                        html += `<th>${key}</th>`;
                    });
                    html += '</tr>';
                    result.results.forEach(row => {
                        html += '<tr>';
                        Object.values(row).forEach(val => {
                            html += `<td>${val}</td>`;
                        });
                        html += '</tr>';
                    });
                    html += '</table>';
                }
                
                if (result.result) {
                    html += '<table class="result-table"><tr>';
                    Object.keys(result.result).forEach(key => {
                        html += `<th>${key}</th>`;
                    });
                    html += '</tr><tr>';
                    Object.values(result.result).forEach(val => {
                        html += `<td>${val}</td>`;
                    });
                    html += '</tr></table>';
                }
                
                if (result.attack_info) {
                    html += `<div class="info-box">Information: ${result.attack_info}</div>`;
                }
            }
            
            document.getElementById(outputId).innerHTML = html;
        }
        
        function updateStats() {
            document.getElementById('totalAttempts').textContent = stats.totalAttempts;
            document.getElementById('vulnBreaches').textContent = stats.vulnBreaches;
            document.getElementById('secureBlocks').textContent = stats.secureBlocks;
        }
        
        function resetAnalysis() {
            document.getElementById('sqlQuery').value = '';
            document.getElementById('vulnOutput').innerHTML = '<div class="placeholder">Enter a SQL query and click Analyze to see results</div>';
            document.getElementById('secureOutput').innerHTML = '<div class="placeholder">Enter a SQL query and click Analyze to see results</div>';
        }
    </script>
</body>
</html>
'''

# -------------------------
# DATABASE SETUP
# -------------------------
def init_db():
    """Initialize database with sample data"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Drop existing tables
    cursor.execute('DROP TABLE IF EXISTS orders')
    cursor.execute('DROP TABLE IF EXISTS products')
    cursor.execute('DROP TABLE IF EXISTS users')
    
    # Create tables
    cursor.execute('''
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT UNIQUE,
            full_name TEXT,
            role TEXT,
            created_at TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE products (
            product_id INTEGER PRIMARY KEY,
            product_name TEXT,
            category TEXT,
            price REAL,
            stock INTEGER,
            description TEXT,
            created_at TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            order_date TEXT,
            total_amount REAL,
            status TEXT,
            shipping_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')
    
    # Insert sample data with bcrypt hashed passwords
    users = [
        (1, 'john_doe', bcrypt.hashpw('pass123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'john@email.com', 'John Doe', 'user', '2024-01-01'),
        (2, 'admin', bcrypt.hashpw('admin@pass'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'admin@company.com', 'Admin User', 'admin', '2024-01-01'),
        (3, 'jane_smith', bcrypt.hashpw('jane@pass'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 'jane@email.com', 'Jane Smith', 'user', '2024-01-05'),
    ]
    cursor.executemany('INSERT INTO users VALUES (?,?,?,?,?,?,?)', users)
    
    products = [
        (1, 'Laptop Pro', 'Electronics', 1299.99, 10, 'High-end laptop', '2024-01-01'),
        (2, 'Wireless Mouse', 'Electronics', 29.99, 150, 'Ergonomic design', '2024-01-02'),
        (3, 'USB Cable', 'Accessories', 9.99, 500, '2-meter cable', '2024-01-03'),
    ]
    cursor.executemany('INSERT INTO products VALUES (?,?,?,?,?,?,?)', products)
    
    orders = [
        (1, 1, '2024-01-15', 1299.99, 'Shipped', '123 Main St, USA'),
        (2, 2, '2024-01-20', 29.99, 'Delivered', '456 Oak Ave, USA'),
    ]
    cursor.executemany('INSERT INTO orders VALUES (?,?,?,?,?,?)', orders)
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# -------------------------
# PASSWORD HASHING FUNCTIONS (bcrypt)
# -------------------------
def hash_password(password: str) -> str:
    """Hash password using bcrypt with automatic salt generation"""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

# -------------------------
# VALIDATION FUNCTIONS
# -------------------------
def validate_numeric_id(value):
    """Validate numeric ID"""
    try:
        id_int = int(value)
        if id_int <= 0:
            return False, None, "ID must be positive"
        return True, id_int, "Valid"
    except (ValueError, TypeError):
        return False, None, f"ID must be a number (you entered: {value})"

def validate_text(text, max_length=100):
    """Validate text input"""
    if text is None:
        return False, f"Text must be 1-{max_length} characters"
    if not isinstance(text, str) or len(text) == 0 or len(text) > max_length:
        return False, f"Text must be 1-{max_length} characters"
    return True, "Valid"

def validate_email(email):
    """Validate email"""
    if not email or len(email) > 100:
        return False, "Invalid email"
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        return False, "Invalid email format"
    return True, "Valid"

# Simple injection pattern detector
INJECTION_PATTERNS = [
    r"(--\s*$)",
    r"(\bOR\b\s+1=1)",
    r"(';)|(\";)",
    r";\s*--",
    r"\bUNION\b",
    r"\bDROP\b",
]

def detect_injection(query):
    """Detect SQL injection patterns"""
    q = (query or "").upper()
    for pat in INJECTION_PATTERNS:
        if re.search(pat, q, flags=re.IGNORECASE):
            return True, pat
    if re.search(r"'\s*--", query) or re.search(r"or\s+1=1", query, flags=re.IGNORECASE):
        return True, "simple-bypass"
    return False, None

# -------------------------
# MAIN PAGE ROUTE
# -------------------------
@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template_string(HTML_TEMPLATE)

# -------------------------
# VULNERABLE ENDPOINTS
# -------------------------
@app.route('/api/vulnerable/login', methods=['POST'])
def vulnerable_login():
    """VULNERABLE: String concatenation in SELECT"""
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # VULNERABLE: String concatenation
        password_hash = hash_password(password)
        query = f"SELECT user_id, username, email, full_name, role FROM users WHERE username='{username}'"
        
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        return jsonify({
            'status': 'success' if result else 'failed',
            'query': query,
            'result': {
                'user_id': result[0],
                'username': result[1],
                'email': result[2],
                'full_name': result[3],
                'role': result[4]
            } if result else None,
            'message': 'Login successful' if result else 'Invalid credentials',
            'attack_info': 'Try: username="admin\' --" to bypass password check'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e), 'query': query})

@app.route('/api/vulnerable/search', methods=['POST'])
def vulnerable_search():
    """VULNERABLE: String concatenation in SELECT WHERE"""
    data = request.json
    product_id = data.get('product_id', '')
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # VULNERABLE: String concatenation
        query = f"SELECT product_id, product_name, category, price, stock FROM products WHERE product_id={product_id}"
        
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'query': query,
            'results': [
                {
                    'product_id': r[0],
                    'product_name': r[1],
                    'category': r[2],
                    'price': r[3],
                    'stock': r[4]
                } for r in results
            ],
            'record_count': len(results),
            'attack_info': 'Try: product_id="1 OR 1=1" to retrieve all products'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e), 'query': query})

@app.route('/api/vulnerable/analyze', methods=['POST'])
def vulnerable_analyze():
    """Execute query using string concatenation (DEMO ONLY)"""
    data = request.json or {}
    query = data.get('query', '')
    
    if not query:
        return jsonify({'status': 'error', 'message': 'No query provided', 'query': ''})
    
    is_injection, pattern = detect_injection(query)
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute(query)
        fetched = cursor.fetchall()
        columns = [d[0] for d in cursor.description] if cursor.description else []
        conn.commit()
        conn.close()
        
        results = []
        for row in fetched:
            if columns:
                results.append({columns[i]: row[i] for i in range(len(row))})
            else:
                results.append(tuple(row))
        
        return jsonify({
            'status': 'success',
            'query': query,
            'results': results,
            'record_count': len(results),
            'is_vulnerable': bool(is_injection),
            'attack_info': f'Detected pattern: {pattern}' if is_injection else 'No simple injection pattern detected'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e), 'query': query, 'is_vulnerable': bool(is_injection)})

# -------------------------
# SECURE ENDPOINTS
# -------------------------
@app.route('/api/secure/login', methods=['POST'])
def secure_login():
    """SECURE: Parameterized query + validation + bcrypt"""
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    is_valid, msg = validate_text(username, max_length=20)
    if not is_valid:
        return jsonify({'status': 'error', 'message': f'Invalid username: {msg}'})
    
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return jsonify({'status': 'error', 'message': 'Username contains invalid characters'})
    
    if not password or len(password) < 5:
        return jsonify({'status': 'error', 'message': 'Invalid password'})
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # SECURE: Parameterized query
        query = "SELECT user_id, username, email, full_name, role, password_hash FROM users WHERE username=?"
        
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        conn.close()
        
        # Verify password using bcrypt
        if result and verify_password(password, result[5]):
            return jsonify({
                'status': 'success',
                'query': query,
                'parameters': [username],
                'result': {
                    'user_id': result[0],
                    'username': result[1],
                    'email': result[2],
                    'full_name': result[3],
                    'role': result[4]
                },
                'message': 'Login successful',
                'protection': 'Parameterized query + Input validation + bcrypt password hashing'
            })
        else:
            return jsonify({
                'status': 'failed',
                'query': query,
                'parameters': [username],
                'message': 'Invalid credentials',
                'protection': 'Parameterized query + Input validation + bcrypt password hashing'
            })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/api/secure/search', methods=['POST'])
def secure_search():
    """SECURE: Parameterized query + type validation"""
    data = request.json
    product_id = data.get('product_id', '')
    
    is_valid, id_int, msg = validate_numeric_id(product_id)
    if not is_valid:
        return jsonify({'status': 'error', 'message': f'Invalid product_id: {msg}'})
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        query = "SELECT product_id, product_name, category, price, stock FROM products WHERE product_id=?"
        
        cursor.execute(query, (id_int,))
        results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'query': query,
            'parameters': [id_int],
            'results': [
                {
                    'product_id': r[0],
                    'product_name': r[1],
                    'category': r[2],
                    'price': r[3],
                    'stock': r[4]
                } for r in results
            ],
            'record_count': len(results),
            'protection': 'Parameterized query + Type validation'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/api/secure/analyze', methods=['POST'])
def secure_analyze():
    """Simulate secure handling with injection detection"""
    data = request.json or {}
    query = data.get('query', '')
    
    if not query:
        return jsonify({'status': 'error', 'message': 'No query provided', 'query': ''})
    
    is_injection, pattern = detect_injection(query)
    if is_injection:
        return jsonify({
            'status': 'error',
            'message': 'Potential SQL injection detected – query blocked by secure layer.',
            'query': query,
            'attack_blocked': True,
            'attack_info': f'Detected pattern: {pattern}'
        })
    
    forbidden = [r";", r"\bDROP\b", r"\bUNION\b", r"\bATTACH\b", r"\bPRAGMA\b"]
    for pat in forbidden:
        if re.search(pat, query, flags=re.IGNORECASE):
            return jsonify({
                'status': 'error',
                'message': 'Query contains forbidden keywords – blocked by secure layer.',
                'query': query,
                'attack_blocked': True,
                'attack_info': f'Forbidden token matched: {pat}'
            })
    
    if not query.strip().upper().startswith('SELECT'):
        return jsonify({
            'status': 'success',
            'message': 'Non-SELECT queries are not executed in secure analyze. Use specific endpoints with parameterized inputs.',
            'query': query,
            'attack_blocked': False,
            'protection': 'Parameterized query + Strict whitelist'
        })
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(query)
        fetched = cursor.fetchall()
        columns = [d[0] for d in cursor.description] if cursor.description else []
        conn.close()
        
        results = []
        for row in fetched:
            if columns:
                results.append({columns[i]: row[i] for i in range(len(row))})
            else:
                results.append(tuple(row))
        
        return jsonify({
            'status': 'success',
            'query': query,
            'results': results,
            'record_count': len(results),
            'attack_blocked': False,
            'protection': 'Secure analyze: only SELECT allowed + injection detection'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'query': query,
            'attack_blocked': True,
            'attack_info': 'Error executing query in secure analyze'
        })

@app.route('/api/reset-db', methods=['POST'])
def reset_db():
    """Reset database to original state"""
    init_db()
    return jsonify({'status': 'success', 'message': 'Database reset to original state'})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("SQL Injection Prevention - Security Testing Platform")
    print("="*60)
    print("\n🚀 Server starting on http://127.0.0.1:5002")
    print("\n📝 To access the application:")
    print("   Open your browser and go to: http://localhost:5002")
    print("\n✨ Features:")
    print("   • Vulnerable vs Secure SQL implementations")
    print("   • Real-time SQL injection detection")
    print("   • Interactive testing interface")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, port=5002, host='127.0.0.1')