from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import os
import hashlib
import io
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'happywiseghala-2024')
CORS(app, supports_credentials=True)


def get_db():
    return psycopg2.connect(
        host=os.environ.get('POSTGRES_HOST', 'localhost'),
        database=os.environ.get('POSTGRES_DB', 'stockdb'),
        user=os.environ.get('POSTGRES_USER', 'stockadmin'),
        password=os.environ.get('POSTGRES_PASSWORD', 'password')
    )


def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS staff (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(64) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'attendant',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS business_config (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT
    )""")

    cur.execute("""
    INSERT INTO business_config (key, value) VALUES
        ('business_name', 'HappywiseGhala'),
        ('business_type', 'retail'),
        ('currency', 'KES'),
        ('allow_negative_stock', 'false')
    ON CONFLICT (key) DO NOTHING
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(300) NOT NULL,
        sku VARCHAR(100),
        barcode VARCHAR(100),
        category_id INT REFERENCES categories(id),
        unit VARCHAR(50) DEFAULT 'pcs',
        buying_price DECIMAL(12,2) DEFAULT 0,
        selling_price DECIMAL(12,2) DEFAULT 0,
        reorder_level DECIMAL(12,2) DEFAULT 10,
        current_stock DECIMAL(12,2) DEFAULT 0,
        expiry_date DATE,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS suppliers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        phone VARCHAR(50),
        email VARCHAR(200),
        address TEXT,
        notes TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stock_in (
        id SERIAL PRIMARY KEY,
        supplier_id INT REFERENCES suppliers(id),
        grn_number VARCHAR(100),
        total_amount DECIMAL(12,2) DEFAULT 0,
        payment_status VARCHAR(50) DEFAULT 'unpaid',
        received_by INT REFERENCES staff(id),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stock_in_items (
        id SERIAL PRIMARY KEY,
        stock_in_id INT REFERENCES stock_in(id) ON DELETE CASCADE,
        product_id INT REFERENCES products(id),
        quantity DECIMAL(12,2) NOT NULL,
        buying_price DECIMAL(12,2) NOT NULL,
        expiry_date DATE
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        phone VARCHAR(50),
        email VARCHAR(200),
        credit_limit DECIMAL(12,2) DEFAULT 0,
        notes TEXT,
        is_archived BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sales (
        id SERIAL PRIMARY KEY,
        customer_id INT REFERENCES customers(id),
        invoice_number VARCHAR(100) UNIQUE,
        total_amount DECIMAL(12,2) DEFAULT 0,
        payment_method VARCHAR(50) DEFAULT 'cash',
        payment_status VARCHAR(50) DEFAULT 'paid',
        served_by INT REFERENCES staff(id),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sale_items (
        id SERIAL PRIMARY KEY,
        sale_id INT REFERENCES sales(id) ON DELETE CASCADE,
        product_id INT REFERENCES products(id),
        quantity DECIMAL(12,2) NOT NULL,
        unit_price DECIMAL(12,2) NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS stock_adjustments (
        id SERIAL PRIMARY KEY,
        product_id INT REFERENCES products(id),
        type VARCHAR(50) NOT NULL,
        quantity DECIMAL(12,2) NOT NULL,
        stock_change DECIMAL(12,2) NOT NULL,
        reason TEXT,
        adjusted_by INT REFERENCES staff(id),
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        action VARCHAR(100) NOT NULL,
        details TEXT,
        performed_by INT REFERENCES staff(id),
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("SELECT COUNT(*) FROM staff")
    if cur.fetchone()[0] == 0:
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        cur.execute("""
        INSERT INTO staff (name, username, password_hash, role)
        VALUES ('Owner', %s, %s, 'owner')
        """, (admin_username, hash_pw(admin_password)))

    conn.commit()
    cur.close()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def log_action(conn, action, details):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log (action, details, performed_by) VALUES (%s,%s,%s)",
        (action, details, session.get('user_id'))
    )
    cur.close()


# ── AUTH ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM staff WHERE username=%s AND is_active=TRUE", (data['username'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user or user['password_hash'] != hash_pw(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    session['user_id'] = user['id']
    session['role'] = user['role']
    session['name'] = user['name']
    return jsonify({'id': user['id'], 'name': user['name'], 'role': user['role']})


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/me')
@login_required
def me():
    return jsonify({'id': session['user_id'], 'name': session['name'], 'role': session['role']})


# ── BUSINESS CONFIG ───────────────────────────────────────────────────────────

@app.route('/config')
@login_required
def get_config():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT key, value FROM business_config")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({r['key']: r['value'] for r in rows})


@app.route('/config', methods=['PUT'])
@login_required
def update_config():
    if session.get('role') not in ('owner',):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor()
    for k, v in data.items():
        cur.execute(
            "INSERT INTO business_config (key,value) VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=%s",
            (k, v, v)
        )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ── CATEGORIES ────────────────────────────────────────────────────────────────

@app.route('/categories')
@login_required
def get_categories():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM categories ORDER BY name")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/categories', methods=['POST'])
@login_required
def add_category():
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("INSERT INTO categories (name,description) VALUES (%s,%s) RETURNING *",
                (data['name'], data.get('description', '')))
    row = cur.fetchone()
    log_action(conn, 'category_added', f"Category: {data['name']}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row), 201


@app.route('/categories/<int:cid>', methods=['PUT'])
@login_required
def update_category(cid):
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE categories SET name=%s,description=%s WHERE id=%s RETURNING *",
                (data['name'], data.get('description', ''), cid))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row)


@app.route('/categories/<int:cid>', methods=['DELETE'])
@login_required
def delete_category(cid):
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM categories WHERE id=%s", (cid,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ── PRODUCTS ──────────────────────────────────────────────────────────────────

@app.route('/products')
@login_required
def get_products():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT p.*, c.name as category_name
        FROM products p
        LEFT JOIN categories c ON p.category_id=c.id
        WHERE p.is_active=TRUE
        ORDER BY p.name
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/products', methods=['POST'])
@login_required
def add_product():
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO products (name,sku,barcode,category_id,unit,buying_price,selling_price,reorder_level,expiry_date)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
    """, (
        data['name'],
        data.get('sku') or None,
        data.get('barcode') or None,
        data.get('category_id') or None,
        data.get('unit', 'pcs'),
        data.get('buying_price', 0),
        data.get('selling_price', 0),
        data.get('reorder_level', 10),
        data.get('expiry_date') or None
    ))
    row = cur.fetchone()
    log_action(conn, 'product_added', f"Product: {data['name']}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row), 201


@app.route('/products/<int:pid>', methods=['PUT'])
@login_required
def update_product(pid):
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        UPDATE products SET name=%s,sku=%s,barcode=%s,category_id=%s,unit=%s,
        buying_price=%s,selling_price=%s,reorder_level=%s,expiry_date=%s
        WHERE id=%s RETURNING *
    """, (
        data['name'],
        data.get('sku') or None,
        data.get('barcode') or None,
        data.get('category_id') or None,
        data.get('unit', 'pcs'),
        data.get('buying_price', 0),
        data.get('selling_price', 0),
        data.get('reorder_level', 10),
        data.get('expiry_date') or None,
        pid
    ))
    row = cur.fetchone()
    log_action(conn, 'product_updated', f"Product ID {pid}: {data['name']}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row)


@app.route('/products/<int:pid>', methods=['DELETE'])
@login_required
def delete_product(pid):
    if session.get('role') not in ('owner',):
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE products SET is_active=FALSE WHERE id=%s", (pid,))
    log_action(conn, 'product_deactivated', f"Product ID {pid}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ── SUPPLIERS ─────────────────────────────────────────────────────────────────

@app.route('/suppliers')
@login_required
def get_suppliers():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM suppliers WHERE is_active=TRUE ORDER BY name")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/suppliers', methods=['POST'])
@login_required
def add_supplier():
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO suppliers (name,phone,email,address,notes)
        VALUES (%s,%s,%s,%s,%s) RETURNING *
    """, (data['name'], data.get('phone',''), data.get('email',''),
          data.get('address',''), data.get('notes','')))
    row = cur.fetchone()
    log_action(conn, 'supplier_added', f"Supplier: {data['name']}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row), 201


@app.route('/suppliers/<int:sid>', methods=['PUT'])
@login_required
def update_supplier(sid):
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        UPDATE suppliers SET name=%s,phone=%s,email=%s,address=%s,notes=%s
        WHERE id=%s RETURNING *
    """, (data['name'], data.get('phone',''), data.get('email',''),
          data.get('address',''), data.get('notes',''), sid))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row)


# ── STOCK IN (GRN) ────────────────────────────────────────────────────────────

@app.route('/stock-in')
@login_required
def get_stock_in():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT si.*, s.name as supplier_name, st.name as received_by_name
        FROM stock_in si
        LEFT JOIN suppliers s ON si.supplier_id=s.id
        LEFT JOIN staff st ON si.received_by=st.id
        ORDER BY si.created_at DESC LIMIT 300
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/stock-in/<int:grn_id>')
@login_required
def get_grn_detail(grn_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT si.*, s.name as supplier_name, st.name as received_by_name
        FROM stock_in si
        LEFT JOIN suppliers s ON si.supplier_id=s.id
        LEFT JOIN staff st ON si.received_by=st.id
        WHERE si.id=%s
    """, (grn_id,))
    grn = dict(cur.fetchone())
    cur.execute("""
        SELECT sii.*, p.name as product_name, p.unit
        FROM stock_in_items sii
        JOIN products p ON sii.product_id=p.id
        WHERE sii.stock_in_id=%s
    """, (grn_id,))
    grn['items'] = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(grn)


@app.route('/stock-in', methods=['POST'])
@login_required
def create_grn():
    if session.get('role') not in ('owner', 'manager', 'attendant'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    items = data.get('items', [])
    if not items:
        return jsonify({'error': 'No items provided'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT COUNT(*)+1 as n FROM stock_in")
    n = cur.fetchone()['n']
    grn_number = data.get('grn_number') or f"GRN-{str(n).zfill(5)}"
    total = sum(float(i['quantity']) * float(i['buying_price']) for i in items)
    cur.execute("""
        INSERT INTO stock_in (supplier_id,grn_number,total_amount,payment_status,received_by,notes)
        VALUES (%s,%s,%s,%s,%s,%s) RETURNING *
    """, (
        data.get('supplier_id') or None,
        grn_number, total,
        data.get('payment_status', 'unpaid'),
        session['user_id'],
        data.get('notes', '')
    ))
    grn = dict(cur.fetchone())
    for item in items:
        cur.execute("""
            INSERT INTO stock_in_items (stock_in_id,product_id,quantity,buying_price,expiry_date)
            VALUES (%s,%s,%s,%s,%s)
        """, (grn['id'], item['product_id'], item['quantity'],
              item['buying_price'], item.get('expiry_date') or None))
        cur.execute(
            "UPDATE products SET current_stock=current_stock+%s, buying_price=%s WHERE id=%s",
            (item['quantity'], item['buying_price'], item['product_id'])
        )
    log_action(conn, 'stock_in', f"GRN {grn_number} — {len(items)} items, KES {total:,.2f}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(grn), 201


@app.route('/stock-in/<int:grn_id>/payment', methods=['PATCH'])
@login_required
def update_grn_payment(grn_id):
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    status = data.get('payment_status', '')
    if status not in ('unpaid', 'partial', 'paid'):
        return jsonify({'error': 'Invalid payment status'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "UPDATE stock_in SET payment_status=%s WHERE id=%s RETURNING grn_number",
        (status, grn_id)
    )
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({'error': 'GRN not found'}), 404
    log_action(conn, 'grn_payment_updated', f"GRN {row['grn_number']} payment → {status}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


@app.route('/stock-in/scan-receipt', methods=['POST'])
@login_required
def scan_receipt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400
    mime = f.content_type or 'image/jpeg'
    if not mime.startswith('image/'):
        return jsonify({'error': 'Only image files are supported'}), 400
    api_key = os.environ.get('GROQ_API_KEY', '')
    if not api_key:
        return jsonify({'error': 'Groq API key not configured on server'}), 500
    try:
        from groq import Groq
        import base64 as _b64
        import json as _json
        import re as _re
        client = Groq(api_key=api_key)
        b64 = _b64.b64encode(f.read()).decode('utf-8')
        prompt = (
            'Extract all line items from this supplier receipt or invoice. '
            'Return ONLY a raw JSON array — no markdown, no explanation. '
            'Each object must have exactly these keys: '
            '"name" (string), "quantity" (number), "unit_price" (number). '
            'If quantity or unit_price cannot be determined use 1 or 0. '
            'Example: [{"name":"Sugar 1kg","quantity":10,"unit_price":2.50}]'
        )
        response = client.chat.completions.create(
            model='meta-llama/llama-4-scout-17b-16e-instruct',
            messages=[{
                'role': 'user',
                'content': [
                    {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{b64}'}},
                    {'type': 'text', 'text': prompt}
                ]
            }],
            max_tokens=1024
        )
        text = response.choices[0].message.content.strip()
        text = _re.sub(r'^```(?:json)?\s*', '', text)
        text = _re.sub(r'\s*```$', '', text)
        items = _json.loads(text)
        if not isinstance(items, list):
            raise ValueError('Unexpected response format')
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── CUSTOMERS ─────────────────────────────────────────────────────────────────

@app.route('/customers')
@login_required
def get_customers():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM customers WHERE is_archived=FALSE ORDER BY name")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/customers', methods=['POST'])
@login_required
def add_customer():
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO customers (name,phone,email,credit_limit,notes)
        VALUES (%s,%s,%s,%s,%s) RETURNING *
    """, (data['name'], data.get('phone',''), data.get('email',''),
          data.get('credit_limit', 0), data.get('notes','')))
    row = cur.fetchone()
    log_action(conn, 'customer_added', f"Customer: {data['name']}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row), 201


@app.route('/customers/<int:cid>', methods=['PUT'])
@login_required
def update_customer(cid):
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        UPDATE customers SET name=%s,phone=%s,email=%s,credit_limit=%s,notes=%s
        WHERE id=%s RETURNING *
    """, (data['name'], data.get('phone',''), data.get('email',''),
          data.get('credit_limit', 0), data.get('notes',''), cid))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row)


# ── SALES ─────────────────────────────────────────────────────────────────────

@app.route('/sales')
@login_required
def get_sales():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT s.*, c.name as customer_name, st.name as served_by_name
        FROM sales s
        LEFT JOIN customers c ON s.customer_id=c.id
        LEFT JOIN staff st ON s.served_by=st.id
        ORDER BY s.created_at DESC LIMIT 300
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/sales/<int:sale_id>')
@login_required
def get_sale_detail(sale_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT s.*, c.name as customer_name, c.phone as customer_phone, st.name as served_by_name
        FROM sales s
        LEFT JOIN customers c ON s.customer_id=c.id
        LEFT JOIN staff st ON s.served_by=st.id
        WHERE s.id=%s
    """, (sale_id,))
    sale = dict(cur.fetchone())
    cur.execute("""
        SELECT si.*, p.name as product_name, p.unit, (si.quantity*si.unit_price) as total
        FROM sale_items si
        JOIN products p ON si.product_id=p.id
        WHERE si.sale_id=%s
    """, (sale_id,))
    sale['items'] = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(sale)


@app.route('/sales', methods=['POST'])
@login_required
def create_sale():
    data = request.json
    items = data.get('items', [])
    if not items:
        return jsonify({'error': 'No items in cart'}), 400
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT value FROM business_config WHERE key='allow_negative_stock'")
    cfg = cur.fetchone()
    allow_neg = cfg and cfg['value'] == 'true'
    if not allow_neg:
        for item in items:
            cur.execute("SELECT name, current_stock FROM products WHERE id=%s", (item['product_id'],))
            p = cur.fetchone()
            if p and float(p['current_stock']) < float(item['quantity']):
                cur.close()
                conn.close()
                return jsonify({'error': f"Insufficient stock for \"{p['name']}\" (available: {p['current_stock']})"}), 400
    cur.execute("SELECT COUNT(*)+1 as n FROM sales")
    n = cur.fetchone()['n']
    inv = f"INV-{str(n).zfill(6)}"
    total = sum(float(i['quantity']) * float(i['unit_price']) for i in items)
    cur.execute("""
        INSERT INTO sales (customer_id,invoice_number,total_amount,payment_method,payment_status,served_by,notes)
        VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *
    """, (
        data.get('customer_id') or None, inv, total,
        data.get('payment_method', 'cash'),
        data.get('payment_status', 'paid'),
        session['user_id'],
        data.get('notes', '')
    ))
    sale = dict(cur.fetchone())
    for item in items:
        cur.execute(
            "INSERT INTO sale_items (sale_id,product_id,quantity,unit_price) VALUES (%s,%s,%s,%s)",
            (sale['id'], item['product_id'], item['quantity'], item['unit_price'])
        )
        cur.execute(
            "UPDATE products SET current_stock=current_stock-%s WHERE id=%s",
            (item['quantity'], item['product_id'])
        )
    cust = f"Customer ID {data.get('customer_id')}" if data.get('customer_id') else "Walk-in"
    log_action(conn, 'sale_created', f"Invoice {inv} — {cust}, KES {total:,.2f}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(sale), 201


# ── STOCK ADJUSTMENTS ─────────────────────────────────────────────────────────

@app.route('/adjustments')
@login_required
def get_adjustments():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT a.*, p.name as product_name, p.unit, st.name as adjusted_by_name
        FROM stock_adjustments a
        JOIN products p ON a.product_id=p.id
        LEFT JOIN staff st ON a.adjusted_by=st.id
        ORDER BY a.created_at DESC LIMIT 300
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/adjustments', methods=['POST'])
@login_required
def create_adjustment():
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden — managers and owners only'}), 403
    data = request.json
    adj_type = data['type']
    qty = float(data['quantity'])
    increase = ('stock_take_surplus', 'return_in')
    stock_change = qty if adj_type in increase else -qty
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO stock_adjustments (product_id,type,quantity,stock_change,reason,adjusted_by)
        VALUES (%s,%s,%s,%s,%s,%s) RETURNING *
    """, (data['product_id'], adj_type, qty, stock_change,
          data.get('reason', ''), session['user_id']))
    row = cur.fetchone()
    cur.execute("UPDATE products SET current_stock=current_stock+%s WHERE id=%s",
                (stock_change, data['product_id']))
    cur.execute("SELECT name FROM products WHERE id=%s", (data['product_id'],))
    p = cur.fetchone()
    log_action(conn, 'stock_adjusted',
               f"{adj_type} on \"{p['name']}\": {stock_change:+.2f}. Reason: {data.get('reason','')}")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row), 201


# ── DASHBOARD ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT COUNT(*) as v FROM products WHERE is_active=TRUE")
    total_products = cur.fetchone()['v']

    cur.execute("SELECT COALESCE(SUM(current_stock*buying_price),0) as v FROM products WHERE is_active=TRUE")
    stock_cost_value = float(cur.fetchone()['v'])

    cur.execute("SELECT COALESCE(SUM(current_stock*selling_price),0) as v FROM products WHERE is_active=TRUE")
    stock_retail_value = float(cur.fetchone()['v'])

    cur.execute("SELECT COALESCE(SUM(total_amount),0) as v FROM sales WHERE DATE(created_at)=CURRENT_DATE")
    today_sales = float(cur.fetchone()['v'])

    cur.execute("SELECT COALESCE(SUM(total_amount),0) as v FROM sales WHERE DATE_TRUNC('month',created_at)=DATE_TRUNC('month',CURRENT_DATE)")
    month_sales = float(cur.fetchone()['v'])

    cur.execute("SELECT COUNT(*) as v FROM products WHERE is_active=TRUE AND current_stock>0 AND current_stock<=reorder_level")
    low_stock_count = cur.fetchone()['v']

    cur.execute("SELECT COUNT(*) as v FROM products WHERE is_active=TRUE AND current_stock=0")
    out_of_stock_count = cur.fetchone()['v']

    cur.execute("SELECT COUNT(*) as v FROM products WHERE is_active=TRUE AND expiry_date IS NOT NULL AND expiry_date BETWEEN CURRENT_DATE AND CURRENT_DATE+INTERVAL '30 days'")
    expiring_soon = cur.fetchone()['v']

    cur.execute("""
        SELECT p.name, p.unit, SUM(si.quantity) as qty_sold, SUM(si.quantity*si.unit_price) as revenue
        FROM sale_items si
        JOIN products p ON si.product_id=p.id
        JOIN sales s ON si.sale_id=s.id
        WHERE DATE_TRUNC('month',s.created_at)=DATE_TRUNC('month',CURRENT_DATE)
        GROUP BY p.id,p.name,p.unit ORDER BY qty_sold DESC LIMIT 5
    """)
    top_products = cur.fetchall()

    cur.execute("""
        SELECT p.name,p.unit,p.current_stock,p.reorder_level,c.name as category_name
        FROM products p LEFT JOIN categories c ON p.category_id=c.id
        WHERE p.is_active=TRUE AND p.current_stock<=p.reorder_level
        ORDER BY p.current_stock ASC LIMIT 10
    """)
    low_stock_items = cur.fetchall()

    cur.execute("""
        SELECT TO_CHAR(d::date,'Mon DD') as day, COALESCE(SUM(s.total_amount),0) as total
        FROM generate_series(CURRENT_DATE-6, CURRENT_DATE, '1 day'::interval) d
        LEFT JOIN sales s ON DATE(s.created_at)=d::date
        GROUP BY d ORDER BY d
    """)
    sales_trend = cur.fetchall()

    cur.execute("""
        SELECT s.invoice_number, COALESCE(c.name,'Walk-in') as customer_name,
               s.total_amount, s.payment_method, s.payment_status, s.created_at
        FROM sales s LEFT JOIN customers c ON s.customer_id=c.id
        ORDER BY s.created_at DESC LIMIT 8
    """)
    recent_sales = cur.fetchall()

    cur.close()
    conn.close()
    return jsonify({
        'total_products': total_products,
        'stock_cost_value': stock_cost_value,
        'stock_retail_value': stock_retail_value,
        'today_sales': today_sales,
        'month_sales': month_sales,
        'low_stock_count': low_stock_count,
        'out_of_stock_count': out_of_stock_count,
        'expiring_soon': expiring_soon,
        'top_products': top_products,
        'low_stock_items': low_stock_items,
        'sales_trend': sales_trend,
        'recent_sales': recent_sales
    })


# ── REPORTS ───────────────────────────────────────────────────────────────────

@app.route('/reports/valuation')
@login_required
def report_valuation():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT p.name,p.sku,p.unit,p.current_stock,p.buying_price,p.selling_price,
               ROUND(p.current_stock*p.buying_price,2) as cost_value,
               ROUND(p.current_stock*p.selling_price,2) as retail_value,
               c.name as category_name
        FROM products p LEFT JOIN categories c ON p.category_id=c.id
        WHERE p.is_active=TRUE ORDER BY cost_value DESC
    """)
    items = cur.fetchall()
    cur.execute("""
        SELECT COALESCE(SUM(current_stock*buying_price),0) as total_cost,
               COALESCE(SUM(current_stock*selling_price),0) as total_retail
        FROM products WHERE is_active=TRUE
    """)
    totals = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify({'items': items, 'totals': totals})


@app.route('/reports/sales')
@login_required
def report_sales():
    from_date = request.args.get('from', datetime.now().replace(day=1).strftime('%Y-%m-%d'))
    to_date   = request.args.get('to',   datetime.now().strftime('%Y-%m-%d'))
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT s.*, COALESCE(c.name,'Walk-in') as customer_name, st.name as served_by_name
        FROM sales s
        LEFT JOIN customers c ON s.customer_id=c.id
        LEFT JOIN staff st ON s.served_by=st.id
        WHERE DATE(s.created_at) BETWEEN %s AND %s
        ORDER BY s.created_at DESC
    """, (from_date, to_date))
    sales = cur.fetchall()
    cur.execute("""
        SELECT COALESCE(SUM(total_amount),0) as total, COUNT(*) as count
        FROM sales WHERE DATE(created_at) BETWEEN %s AND %s
    """, (from_date, to_date))
    summary = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify({'sales': sales, 'summary': summary})


@app.route('/reports/purchases')
@login_required
def report_purchases():
    from_date = request.args.get('from', datetime.now().replace(day=1).strftime('%Y-%m-%d'))
    to_date   = request.args.get('to',   datetime.now().strftime('%Y-%m-%d'))
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT si.*, COALESCE(s.name,'—') as supplier_name, st.name as received_by_name
        FROM stock_in si
        LEFT JOIN suppliers s ON si.supplier_id=s.id
        LEFT JOIN staff st ON si.received_by=st.id
        WHERE DATE(si.created_at) BETWEEN %s AND %s
        ORDER BY si.created_at DESC
    """, (from_date, to_date))
    purchases = cur.fetchall()
    cur.execute("""
        SELECT COALESCE(SUM(total_amount),0) as total, COUNT(*) as count
        FROM stock_in WHERE DATE(created_at) BETWEEN %s AND %s
    """, (from_date, to_date))
    summary = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify({'purchases': purchases, 'summary': summary})


@app.route('/reports/profit')
@login_required
def report_profit():
    from_date = request.args.get('from', datetime.now().replace(day=1).strftime('%Y-%m-%d'))
    to_date   = request.args.get('to',   datetime.now().strftime('%Y-%m-%d'))
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT p.name, p.unit,
               SUM(si.quantity) as qty_sold,
               ROUND(SUM(si.quantity*si.unit_price),2) as revenue,
               ROUND(SUM(si.quantity*p.buying_price),2) as cost,
               ROUND(SUM(si.quantity*si.unit_price) - SUM(si.quantity*p.buying_price),2) as profit
        FROM sale_items si
        JOIN products p ON si.product_id=p.id
        JOIN sales s ON si.sale_id=s.id
        WHERE DATE(s.created_at) BETWEEN %s AND %s
        GROUP BY p.id,p.name,p.unit ORDER BY profit DESC
    """, (from_date, to_date))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/reports/slow-moving')
@login_required
def report_slow_moving():
    days = int(request.args.get('days', 30))
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"""
        SELECT p.name,p.unit,p.current_stock,p.buying_price,
               ROUND(p.current_stock*p.buying_price,2) as tied_value,
               MAX(s.created_at) as last_sale_date,
               c.name as category_name
        FROM products p
        LEFT JOIN categories c ON p.category_id=c.id
        LEFT JOIN sale_items si ON p.id=si.product_id
        LEFT JOIN sales s ON si.sale_id=s.id
        WHERE p.is_active=TRUE AND p.current_stock>0
        GROUP BY p.id,p.name,p.unit,p.current_stock,p.buying_price,c.name
        HAVING MAX(s.created_at) < NOW()-INTERVAL '{days} days' OR MAX(s.created_at) IS NULL
        ORDER BY tied_value DESC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


# ── STAFF ─────────────────────────────────────────────────────────────────────

@app.route('/staff')
@login_required
def get_staff():
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id,name,username,role,is_active,created_at FROM staff ORDER BY name")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


@app.route('/staff', methods=['POST'])
@login_required
def add_staff():
    if session.get('role') not in ('owner',):
        return jsonify({'error': 'Forbidden — owner only'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO staff (name,username,password_hash,role)
        VALUES (%s,%s,%s,%s) RETURNING id,name,username,role,is_active,created_at
    """, (data['name'], data['username'], hash_pw(data['password']), data['role']))
    row = cur.fetchone()
    log_action(conn, 'staff_added', f"Staff: {data['name']} ({data['role']})")
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row), 201


@app.route('/staff/<int:sid>', methods=['PUT'])
@login_required
def update_staff(sid):
    if session.get('role') not in ('owner',):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("UPDATE staff SET role=%s,is_active=%s WHERE id=%s RETURNING id,name,role,is_active",
                (data['role'], data['is_active'], sid))
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(row)


@app.route('/staff/<int:sid>/reset-password', methods=['POST'])
@login_required
def reset_password(sid):
    if session.get('role') not in ('owner',):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE staff SET password_hash=%s WHERE id=%s", (hash_pw(data['password']), sid))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# ── AUDIT LOG ─────────────────────────────────────────────────────────────────

@app.route('/audit-log')
@login_required
def get_audit_log():
    if session.get('role') not in ('owner', 'manager'):
        return jsonify({'error': 'Forbidden'}), 403
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT a.*, s.name as performed_by_name
        FROM audit_log a LEFT JOIN staff s ON a.performed_by=s.id
        ORDER BY a.created_at DESC LIMIT 500
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(rows)


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
