from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_mysqldb import MySQL
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv
from functools import wraps
import hashlib, os, binascii

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'vaultSecretKey2024!')
AES_KEY = os.getenv('AES_KEY', 'ExactlySixteen12').encode()

app.config['MYSQL_HOST']        = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER']        = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD']    = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB']          = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# ── Helpers ───────────────────────────────────────────

def sha2(text):
    return hashlib.sha256(text.encode()).hexdigest()

def aes_encrypt(text):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct = cipher.encrypt(pad(text.encode(), AES.block_size))
    return cipher.iv + ct

def aes_decrypt(blob):
    if not blob:
        return ''
    iv, ct = bytes(blob[:16]), bytes(blob[16:])
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def log_action(action, table, record_id=None):
    if 'user_id' not in session:
        return
    cur = mysql.connection.cursor()
    cur.execute(
        'INSERT INTO audit_log (user_id,action,table_name,record_id,ip_address)'
        ' VALUES (%s,%s,%s,%s,%s)',
        (session['user_id'], action, table, record_id, request.remote_addr)
    )
    mysql.connection.commit()

def login_required(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if roles and session.get('role') not in roles:
                return render_template('denied.html'), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ── Auth ──────────────────────────────────────────────

@app.route('/', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        cur = mysql.connection.cursor()
        cur.execute(
            'SELECT * FROM users WHERE username=%s AND password_hash=%s',
            (request.form['username'], sha2(request.form['password']))
        )
        user = cur.fetchone()
        if user:
            session.update({
                'user_id':     user['user_id'],
                'username':    user['username'],
                'role':        user['role'],
                'merchant_id': user['merchant_id']
            })
            log_action('LOGIN', 'users', user['user_id'])
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_action('LOGOUT', 'users', session.get('user_id'))
    session.clear()
    return redirect(url_for('login'))

# ── Dashboard ─────────────────────────────────────────

@app.route('/dashboard')
@login_required()
def dashboard():
    return render_template('dashboard.html')

# ── Customers ─────────────────────────────────────────

@app.route('/customers')
@login_required(roles=['admin','merchant'])
def customers():
    cur = mysql.connection.cursor()
    if session['role'] == 'admin':
        cur.execute('SELECT * FROM vw_customer_summary')
    else:
        cur.execute(
            'SELECT * FROM vw_customer_summary WHERE business_name='
            '(SELECT business_name FROM merchants WHERE merchant_id=%s)',
            (session['merchant_id'],)
        )
    return render_template('customers.html', customers=cur.fetchall())

@app.route('/customers/add', methods=['GET','POST'])
@login_required(roles=['admin','merchant'])
def add_customer():
    if request.method == 'POST':
        f   = request.form
        mid = session['merchant_id'] or 1
        cur = mysql.connection.cursor()
        cur.execute(
            'INSERT INTO customers (merchant_id,full_name,email,phone)'
            ' VALUES (%s,%s,%s,%s)',
            (mid, f['full_name'], f['email'], f['phone'])
        )
        mysql.connection.commit()
        log_action('INSERT', 'customers', cur.lastrowid)
        flash('Customer added successfully.')
        return redirect(url_for('customers'))
    return render_template('add_customer.html')

# ── Cards ─────────────────────────────────────────────

@app.route('/cards')
@login_required(roles=['admin','merchant'])
def cards():
    cur = mysql.connection.cursor()
    cur.execute(
        'SELECT cr.*, c.full_name FROM cards cr'
        ' JOIN customers c ON cr.customer_id=c.customer_id'
        ' WHERE c.merchant_id=%s',
        (session['merchant_id'],)
    )
    rows = cur.fetchall()
    for r in rows:
        r['expiry']      = aes_decrypt(r['expiry_enc'])
        r['billing']     = aes_decrypt(r['billing_enc'])
        r['card_number'] = (
            aes_decrypt(r['card_number_enc'])
            if session['role'] == 'admin'
            else '**** **** **** ' + r['last_four']
        )
    return render_template('cards.html', cards=rows)

@app.route('/cards/add', methods=['GET','POST'])
@login_required(roles=['admin','merchant'])
def add_card():
    cur = mysql.connection.cursor()
    mid = session['merchant_id'] or 1
    cur.execute(
        'SELECT customer_id,full_name FROM customers WHERE merchant_id=%s', (mid,)
    )
    cust_list = cur.fetchall()
    if request.method == 'POST':
        f       = request.form
        cardnum = f['card_number'].replace(' ', '')
        token   = binascii.hexlify(os.urandom(16)).decode()
        cur.execute(
            'INSERT INTO cards (customer_id,card_token,card_type,last_four,'
            'expiry_enc,card_number_enc,cvv_enc,billing_enc)'
            ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
            (
                f['customer_id'], token, f['card_type'], cardnum[-4:],
                aes_encrypt(f['expiry']),
                aes_encrypt(cardnum),
                aes_encrypt(f['cvv']),
                aes_encrypt(f['billing'])
            )
        )
        mysql.connection.commit()
        log_action('INSERT', 'cards', cur.lastrowid)
        flash('Card encrypted and saved. Token: ' + token)
        return redirect(url_for('cards'))
    return render_template('add_card.html', customers=cust_list)

# ── Invoices ──────────────────────────────────────────

@app.route('/invoices')
@login_required(roles=['admin','merchant','cashier'])
def invoices():
    cur = mysql.connection.cursor()
    if session['role'] == 'admin':
        cur.execute('SELECT * FROM vw_invoice_history ORDER BY created_at DESC')
    else:
        cur.execute(
            'SELECT * FROM vw_invoice_history WHERE business_name='
            '(SELECT business_name FROM merchants WHERE merchant_id=%s)'
            ' ORDER BY created_at DESC',
            (session['merchant_id'],)
        )
    return render_template('invoices.html', invoices=cur.fetchall())

@app.route('/invoices/create', methods=['GET','POST'])
@login_required(roles=['admin','merchant'])
def create_invoice():
    cur = mysql.connection.cursor()
    mid = session['merchant_id'] or 1
    cur.execute(
        'SELECT customer_id,full_name FROM customers WHERE merchant_id=%s', (mid,)
    )
    cust_list = cur.fetchall()
    card_list = []
    cid = request.args.get('customer_id') or request.form.get('customer_id')
    if cid:
        cur.execute(
            'SELECT card_id,card_type,last_four FROM cards'
            ' JOIN customers c USING(customer_id) WHERE c.customer_id=%s', (cid,)
        )
        card_list = cur.fetchall()
    if request.method == 'POST' and request.form.get('card_id'):
        f = request.form
        cur.execute(
            'INSERT INTO invoices (merchant_id,customer_id,card_id,amount)'
            ' VALUES (%s,%s,%s,%s)',
            (mid, f['customer_id'], f['card_id'], f['amount'])
        )
        mysql.connection.commit()
        log_action('INSERT', 'invoices', cur.lastrowid)
        flash('Invoice created successfully.')
        return redirect(url_for('invoices'))
    return render_template('create_invoice.html', customers=cust_list,
                           cards=card_list, selected_cid=cid)

@app.route('/invoices/update')
@login_required(roles=['admin','merchant'])
def update_invoice():
    inv_id = request.args.get('id')
    status = request.args.get('status')
    if status in ('paid', 'failed', 'pending'):
        cur = mysql.connection.cursor()
        cur.execute(
            'UPDATE invoices SET status=%s WHERE invoice_id=%s', (status, inv_id)
        )
        mysql.connection.commit()
        log_action('UPDATE-' + status, 'invoices', inv_id)
    return redirect(url_for('invoices'))

# ── Audit Log ─────────────────────────────────────────

@app.route('/audit')
@login_required(roles=['admin','auditor'])
def audit():
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM vw_audit_trail LIMIT 200')
    return render_template('audit.html', logs=cur.fetchall())

# ── Run ───────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
