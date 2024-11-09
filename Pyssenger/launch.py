import getpass
import os
from functools import wraps
import random
from datetime import datetime
import hashlib
import string
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import pyzipper
import shutil

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
users = db
# Create necessary directories
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Keys folder setup
KEYS_FOLDER = 'keys'
if not os.path.exists(KEYS_FOLDER):
    os.makedirs(KEYS_FOLDER)

ZIP_FILENAME = "Keys.zip"
PRIVATE_KEY_FILE = 'private_key.pem'
PUBLIC_KEY_FILE = 'public_key.pem'

# Paths for temporary key storage
PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, PRIVATE_KEY_FILE)
PUBLIC_KEY_PATH = os.path.join(KEYS_FOLDER, PUBLIC_KEY_FILE)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True)
    background_image = db.Column(db.String(200), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    secret_phrase_hash = db.Column(db.String(200), nullable=True)
    is_banned = db.Column(db.Boolean, default=False)  # New column
    ban_reason = db.Column(db.String(200), nullable=True)  # New column



# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    aes_key_encrypted = db.Column(db.Text, nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(100), nullable=True)


class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    created_by = db.Column(db.String(50), nullable=False)
    invite_code = db.Column(db.String(20), unique=True, nullable=False)
    is_private = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ChannelMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)


class ChannelMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    aes_key_encrypted = db.Column(db.Text, nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Add these new routes after your existing routes

def generate_invite_code():
    """Generate a random invite code"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))


def encode_and_hash_password(password):
    base64_encoded = base64.b64encode(password.encode('utf-8'))
    return hashlib.sha256(base64_encoded).digest()


def create_zip_with_password(zip_filename, files_to_add, password):
    """Creates an encrypted ZIP file with the given files and password."""
    # Encode password with Base64, then hash with SHA-256
    base64_encoded = base64.b64encode(password.encode('utf-8'))
    sha256_hashed_password = hashlib.sha256(base64_encoded).digest()

    with pyzipper.AESZipFile(zip_filename, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(sha256_hashed_password)
        for item in files_to_add:
            item = item.strip()
            if os.path.exists(item):
                if os.path.isdir(item):
                    for foldername, _, filenames in os.walk(item):
                        for filename in filenames:
                            file_path = os.path.join(foldername, filename)
                            # Create the correct archive path without duplicating folders
                            arcname = os.path.join(os.path.basename(item), filename)
                            zf.write(file_path, arcname=arcname)
                else:
                    # For individual files
                    zf.write(item, arcname=os.path.basename(item))


def generate_and_save_keys(password):
    """Generates RSA keys, saves them to files, and creates an encrypted ZIP"""
    # Create the keys folder if it doesn't exist
    os.makedirs(KEYS_FOLDER, exist_ok=True)

    # Generate new RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save keys to temporary files
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Create ZIP file with keys
    hashed_password = encode_and_hash_password(password)
    with pyzipper.AESZipFile(ZIP_FILENAME, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(hashed_password)

        # Add key files to ZIP archive with the correct relative paths
        zf.write(PRIVATE_KEY_PATH, arcname=PRIVATE_KEY_FILE)
        zf.write(PUBLIC_KEY_PATH, arcname=PUBLIC_KEY_FILE)

    # Clean up temporary files
    if os.path.exists(PRIVATE_KEY_PATH):
        os.remove(PRIVATE_KEY_PATH)
    if os.path.exists(PUBLIC_KEY_PATH):
        os.remove(PUBLIC_KEY_PATH)
    if os.path.exists(KEYS_FOLDER):
        shutil.rmtree(KEYS_FOLDER)

    print("New keys generated and saved in an encrypted ZIP.")
    return private_key, public_key


def load_keys_from_zip(zip_filename, password):
    """Loads keys from the encrypted ZIP file"""
    hashed_password = encode_and_hash_password(password)

    try:
        with pyzipper.AESZipFile(zip_filename) as zf:
            zf.setpassword(hashed_password)

            # Load the private key
            private_key_data = zf.read(f"{PRIVATE_KEY_FILE}")
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )

            # Load the public key
            public_key_data = zf.read(f"{PUBLIC_KEY_FILE}")
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )

        return private_key, public_key

    except KeyError as e:
        print(f"Error: Key files not found in the ZIP - {e}")
    except Exception as e:
        print(f"Error loading keys: {e}")
    return None, None


# Initialize keys if ZIP file exists, otherwise generate and save new ones
def initialize_keys(password):
    if not os.path.exists(ZIP_FILENAME):
        print("ZIP file not found. Generating new keys...")
        return generate_and_save_keys(password)

    private_key, public_key = load_keys_from_zip(ZIP_FILENAME, password)
    if private_key and public_key:
        print("Keys loaded successfully.")
        return private_key, public_key
    else:
        print("Generating new keys due to error...")
        return generate_and_save_keys(password)

# Rest of your encryption/decryption functions remain the same
def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')


def decrypt_aes_key(encrypted_aes_key, private_key):
    encrypted_key_bytes = base64.b64decode(encrypted_aes_key)
    aes_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def encrypt_message_with_aes(message, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode('utf-8')


def decrypt_message_with_aes(encrypted_message, aes_key):
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    iv = encrypted_message_bytes[:16]
    encrypted_message = encrypted_message_bytes[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session or not session['admin_authenticated']:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


def initialize_admin(admin_username, admin_password, secret_phrase):
    """Initialize admin account with provided credentials"""
    with app.app_context():
        # Check if admin already exists
        existing_admin = User.query.filter_by(username=admin_username).first()
        if existing_admin:
            print("Error: Admin username already exists!")
            return False

        # Create admin user
        admin_user = User(
            username=admin_username,
            password_hash=generate_password_hash(admin_password),
            is_admin=True,
            secret_phrase_hash=generate_password_hash(secret_phrase)
        )

        try:
            db.session.add(admin_user)
            db.session.commit()
            print("Admin account created successfully!")
            return True
        except Exception as e:
            print(f"Error creating admin account: {e}")
            db.session.rollback()
            return False

def ban_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in session:
            user = User.query.filter_by(username=session['username']).first()
            if user and user.is_banned:
                session.clear()
                flash(f'Your account has been banned. Reason: {user.ban_reason}')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Get password and initialize keys


# Initialize database
with app.app_context():
    db.create_all()


# Your route handlers remain the same
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        session['username'] = username
        return redirect(url_for('index'))

    return render_template('auth.html', page='signup')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if user.is_banned:
                flash(f'Your account has been banned. Reason: {user.ban_reason}')
                return redirect(url_for('login'))
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))

    return render_template('auth.html', page='login')

@app.route('/about', methods=['GET'])
@ban_check
def about():
    return render_template('about.html')


@app.route('/create-channel', methods=['POST'])
@ban_check
def create_channel():
    if 'username' not in session:
        return redirect(url_for('login'))

    name = request.form['name']
    description = request.form.get('description', '')
    is_private = request.form.get('is_private', True, type=bool)

    # Create channel
    invite_code = generate_invite_code()
    channel = Channel(
        name=name,
        description=description,
        created_by=session['username'],
        invite_code=invite_code,
        is_private=is_private
    )
    db.session.add(channel)
    db.session.commit()

    # Add creator as channel admin
    member = ChannelMember(
        channel_id=channel.id,
        username=session['username'],
        is_admin=True
    )
    db.session.add(member)
    db.session.commit()

    return redirect(url_for('channel', channel_id=channel.id))


@app.route('/channel/<int:channel_id>')
@ban_check
def channel(channel_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    channel = Channel.query.get_or_404(channel_id)
    member = ChannelMember.query.filter_by(
        channel_id=channel_id,
        username=session['username']
    ).first()

    if not member and channel.is_private:
        flash('You are not a member of this channel')
        return redirect(url_for('index'))

    messages = ChannelMessage.query.filter_by(channel_id=channel_id).all()
    for message in messages:
        aes_key = decrypt_aes_key(message.aes_key_encrypted, private_key)
        message.content = decrypt_message_with_aes(message.content_encrypted, aes_key)

    return render_template('channel.html', channel=channel, messages=messages, member=member)


@app.route('/channels')
@ban_check
def channels():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get channels the user is a member of
    member_channels = Channel.query.join(ChannelMember).filter(
        ChannelMember.username == session['username']
    ).all()

    # Get public channels
    public_channels = Channel.query.filter_by(is_private=False).all()

    # Combine and remove duplicates
    all_channels = list(set(member_channels + public_channels))

    return render_template('channels.html', channels=all_channels)


@app.route('/update-channel/<int:channel_id>', methods=['POST'])
@ban_check
def update_channel(channel_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    channel = Channel.query.get_or_404(channel_id)
    member = ChannelMember.query.filter_by(
        channel_id=channel_id,
        username=session['username'],
        is_admin=True
    ).first()

    if not member:
        flash('You do not have permission to modify this channel')
        return redirect(url_for('channel', channel_id=channel_id))

    channel.name = request.form['name']
    channel.description = request.form.get('description', '')
    channel.is_private = 'is_private' in request.form

    db.session.commit()
    flash('Channel settings updated successfully')

    return redirect(url_for('channel', channel_id=channel_id))

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, is_admin=True).first()

        # Add debugging prints
        print(f"Login attempt for admin user: {username}")
        print(f"User found in database: {user is not None}")

        if user and check_password_hash(user.password_hash, password):
            print("Password verification successful")
            session['admin_username'] = username
            return redirect(url_for('secret_phrase'))
        else:
            if user:
                print("Password verification failed")
            flash('Invalid admin credentials')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/admin/ban-user/<int:user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    if not user.is_admin:  # Prevent banning admin users
        user.is_banned = True
        user.ban_reason = request.form.get('ban_reason', 'No reason provided')
        db.session.commit()
        flash(f'User {user.username} has been banned')
    return redirect(url_for('admin_panel'))

@app.route('/admin/unban-user/<int:user_id>')
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_reason = None
    db.session.commit()
    flash(f'User {user.username} has been unbanned')
    return redirect(url_for('admin_panel'))





@app.route('/secret-phrase', methods=['GET', 'POST'])
def secret_phrase():
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        phrase = request.form['secret_phrase']
        user = User.query.filter_by(username=session['admin_username'], is_admin=True).first()

        if user and check_password_hash(user.secret_phrase_hash, phrase):
            session['admin_authenticated'] = True
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid secret phrase')
            return redirect(url_for('secret_phrase'))

    return render_template('secret_phrase.html')


@app.route('/join-channel/<invite_code>')
@ban_check
def join_channel(invite_code):
    if 'username' not in session:
        return redirect(url_for('login'))

    channel = Channel.query.filter_by(invite_code=invite_code).first_or_404()

    # Check if already a member
    existing_member = ChannelMember.query.filter_by(
        channel_id=channel.id,
        username=session['username']
    ).first()

    if not existing_member:
        member = ChannelMember(
            channel_id=channel.id,
            username=session['username']
        )
        db.session.add(member)
        db.session.commit()
        flash('Successfully joined the channel!')

    return redirect(url_for('channel', channel_id=channel.id))


@app.route('/channel/<int:channel_id>/message', methods=['POST'])
@ban_check
def channel_message(channel_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    member = ChannelMember.query.filter_by(
        channel_id=channel_id,
        username=session['username']
    ).first()

    if not member:
        flash('You are not a member of this channel')
        return redirect(url_for('index'))

    content = request.form.get('content', '')
    file = request.files.get('file')

    aes_key = os.urandom(32)
    encrypted_content = encrypt_message_with_aes(content, aes_key)
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

    filename = None
    if file:
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    message = ChannelMessage(
        channel_id=channel_id,
        username=session['username'],
        aes_key_encrypted=encrypted_aes_key,
        content_encrypted=encrypted_content,
        filename=filename
    )
    db.session.add(message)
    db.session.commit()

    return redirect(url_for('channel', channel_id=channel_id))


@app.route('/admin-panel')
@admin_required
def admin_panel():
    users = User.query.all()
    messages = Message.query.all()

    # Decrypt messages for admin view
    for message in messages:
        aes_key = decrypt_aes_key(message.aes_key_encrypted, private_key)
        message.content = decrypt_message_with_aes(message.content_encrypted, aes_key)

    return render_template('panel.html', users=users, messages=messages)


@app.route('/admin/delete-user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if not user.is_admin:  # Prevent deletion of admin users
        Message.query.filter_by(username=user.username).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete-message/<int:message_id>')
@admin_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    flash('Message deleted successfully')
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = User.query.filter_by(username=session['username']).first()

        # Handle profile picture upload
        profile_pic = request.files.get('profile_picture')
        if profile_pic:
            profile_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_pic.filename)
            profile_pic.save(profile_pic_path)
            user.profile_picture = profile_pic.filename

        # Handle background image upload
        bg_image = request.files.get('background_image')
        if bg_image:
            bg_image_path = os.path.join(app.config['UPLOAD_FOLDER'], bg_image.filename)
            bg_image.save(bg_image_path)
            user.background_image = bg_image.filename

        db.session.commit()
        flash('Settings updated successfully')
        return redirect(url_for('settings'))

    return render_template('settings.html')


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/', methods=['GET', 'POST'])
@ban_check
def index():
    if 'username' not in session:
        return render_template('index.html', logged_in=False)

    if request.method == 'POST':
        username = session['username']
        content = request.form.get('content', '')
        file = request.files['file']

        aes_key = os.urandom(32)
        encrypted_content = encrypt_message_with_aes(content, aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        filename = None
        if file:
            filename = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_message = Message(username=username, aes_key_encrypted=encrypted_aes_key, content_encrypted=encrypted_content, filename=filename)
        db.session.add(new_message)
        db.session.commit()

        return redirect(url_for('index'))

    messages = Message.query.all()
    for message in messages:
        aes_key = decrypt_aes_key(message.aes_key_encrypted, private_key)
        message.content = decrypt_message_with_aes(message.content_encrypted, aes_key)

    return render_template('index.html', messages=messages, logged_in=True)


@app.route('/get_new_messages', methods=['GET'])
def get_new_messages():
    last_id = request.args.get('last_id', 0, type=int)
    new_messages = Message.query.filter(Message.id > last_id).all()

    messages_data = []
    for message in new_messages:
        aes_key = decrypt_aes_key(message.aes_key_encrypted, private_key)
        decrypted_content = decrypt_message_with_aes(message.content_encrypted, aes_key)
        messages_data.append({
            'id': message.id,
            'username': message.username,
            'content': decrypted_content,
            'filename': message.filename
        })

    return jsonify(messages_data)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Get password and initialize keys
        password = getpass.getpass("Enter encryption password: ")
        private_key, public_key = initialize_keys(password)

        # Check if admin exists
        admin_exists = User.query.filter_by(is_admin=True).first()
        if not admin_exists:
            print("\n=== Admin Registration ===")
            admin_username = input("Enter admin username: ")
            admin_password = getpass.getpass("Enter admin password: ")
            secret_phrase = input("Enter admin secret phrase: ")

            if initialize_admin(admin_username, admin_password, secret_phrase):
                print("Admin initialization completed successfully")
            else:
                print("Failed to initialize admin account")

    app.run(debug=True)