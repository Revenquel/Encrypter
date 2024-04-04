from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = 'your_flask_secret_key_here'  # Flask session security key

hashed_password = generate_password_hash('4a5ff9fe!A')
check = check_password_hash(hashed_password, '4a5ff9fe!A')

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server encountered an internal error: {error}")
    return render_template('500.html'), 500  # You can create a 500.html template for this.

@app.route('/', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])


def login():
    if request.method == 'POST':
        password = request.form['password']
        # Replace 'hashed_password_here' with the full hashed password string you generated earlier
        hashed_password = 'scrypt:32768:8:1$6nhHwxlvZIN8cm92$dc88fc3ec9ac49d42cbae82c1f5415d14511ddb881b765e6da0cb250dc120a71ea9fca5bb8acbe080a1a67cd1edf6de81588a4ca81e202921773134094a45d31'
        if check_password_hash(hashed_password, password):
            session['authenticated'] = True
            return redirect(url_for('form'))
        else:
            flash('Incorrect password', 'error')
    return render_template('login.html')

@app.route('/form')
def form():
    if not session.get('authenticated'):
        flash('You must log in to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('form.html')

def generate_fernet_key(passphrase: str, salt: bytes) -> bytes:
    """Generate a Fernet key based on the provided passphrase and salt."""
    # Convert the passphrase to bytes
    passphrase_bytes = passphrase.encode()
    # Use PBKDF2HMAC to generate a key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase_bytes))

@app.route('/process', methods=['POST'])
def process():
    if not session.get('authenticated'):
        flash('You must log in to access this page.', 'error')
        return redirect(url_for('login'))

    passphrase = request.form['secret_key']
    input_text = request.form['input_text']
    operation = request.form['operation']

    # Use a static salt for this example, but in a real application, you would want a unique salt per user
    salt = b'your_static_salt_here'  # Replace with a salt of your choice

    try:
        # Generate a Fernet key using the passphrase and salt
        key = generate_fernet_key(passphrase, salt)
        f = Fernet(key)
        if operation == 'encrypt':
            result = f.encrypt(input_text.encode()).decode()
        elif operation == 'decrypt':
            result = f.decrypt(input_text.encode()).decode()
    except Exception as e:
        flash(f'An error occurred: {e}', 'error')
        return redirect(url_for('form'))

    return render_template('result.html', result=result, operation=operation)

if __name__ == '__main__':
    app.run(debug=True)
