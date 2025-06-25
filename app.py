from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, send_from_directory, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from logger import log_action
from datetime import datetime
from functools import wraps
from io import BytesIO
import qrcode
import base64
import json
import os

# Flask config ve veritabanı bağlantısı
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SECRET_KEY'] = 'supersecretkey'  # Flask için secret key
app.config['UPLOAD_FOLDER'] = 'instance/uploads/'
app.config['SESSION_PERMANENT'] = False
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)  # Giriş yapılmadan erişilen sayfalarda yönlendirilecek sayfa
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
    return dict(current_user=user)

# Resim yükleme klasörünün mevcut olduğundan emin ol
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Kullanıcı ve yetki modelleri
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'admin' or 'user'
    approved = db.Column(db.Boolean, default=False)  # Admin onayı

# Envanterler için veritabanı modeli
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), default="Elektronik", nullable=False)
    department = db.Column(db.String(100), default="Fen Fakültesi", nullable=False)
    location = db.Column(db.String(100), default="Depoda", nullable=False)
    serial_number = db.Column(db.String(50), unique=True, nullable=False)
    assigned_to = db.Column(db.String(100), default="Zimmetli değil", nullable=True)
    status = db.Column(db.String(50), default="Depoda")
    notes = db.Column(db.String(300))
    image_filename = db.Column(db.String(300))
    qrkod = db.Column(db.String(300))  # QR kod dosyası
    purchase_date = db.Column(db.Date, default=datetime.today)
    purchase_price = db.Column(db.String(100), default="Bilinmiyor", nullable=True)
    warranty_end = db.Column(db.Date, default=datetime.today)
    supplier = db.Column(db.String(100), nullable=True)
    maintenance_required = db.Column(db.String(100), default="Standart bakımlar", nullable=True)
    
# InventoryLog Model (Envanter işlemleri için)
class InventoryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    inventory_id = db.Column(db.Integer, db.ForeignKey('inventory.id', ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    details = db.Column(db.Text)  # Ekstra detaylar için
    
    inventory = db.relationship("Inventory", backref=db.backref("logs", cascade="all, delete-orphan"))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    user_email = db.Column(db.String(150), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # Ekleme, Güncelleme, Silme vb.
    entity_type = db.Column(db.String(50), nullable=False)  # Envanter, Kullanıcı vb.
    entity_id = db.Column(db.Integer, nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<Log {self.action} {self.entity_type} ID: {self.entity_id}>"

# Login required decorator
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Lütfen giriş yapın.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper
    
# Admin required decorator
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin girişi gerekli.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

# Kullanıcı girişini yöneten login manager
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, session['user_id'])

# Routes

# Kullanıcı Kaydı
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not email or not password:
            flash('Email ve şifre gereklidir!', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, role='user', approved=False)
        db.session.add(new_user)
        db.session.commit()
        # Log kaydı ekle
        log_action(db, Log, "Login", "Kullanıcı", new_user.id, f"{new_user.email} kullanıcısı sisteme kayıt yaptı.")
        flash('Kayıt başarıyla oluşturuldu. Admin onayını bekleyiniz.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html')

# Kullanıcı Girişi
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
        	if user.approved:
        		login_user(user)
        		session['user_id'] = user.id  # Oturumda user_id'yi kaydet
        		session['role'] = user.role  # Oturumda user_role'u kaydet
        		flash('Giriş başarılı!', 'success')
        		# Log kaydı ekle
        		log_action(db, Log, "Login", "Kullanıcı", user.id, f"{current_user.email} kullanıcısı sisteme giriş yaptı.")
        		return redirect(url_for('index'))
        	else:
        		flash('Hesabınız onaylanmadı.', 'warning')
        else:
        	flash('Geçersiz giriş bilgileri.', 'danger')
        # Log kaydı ekle
        log_action(db, Log, "Login", "Kullanıcı", user.id, f"{email} kullanıcısı sisteme başarısız giriş denemesi yaptı.")
    return render_template('login.html')
        
@app.route('/approve_users')
@login_required
@admin_required
def approve_users():
    users = User.query.all()
    return render_template('approve_users.html', users=users)

@app.route('/admin/approve/<int:id>')
@login_required
@admin_required
def approve(id):
    user = db.session.get(User, id)
    if not user:
    	abort(404)
    user.approved = True
    db.session.commit()
    # Log kaydı ekle
    log_action(db, Log, "Login", "Kullanıcı", current_user.id, f"{current_user.email} admin kullanıcısı {user.email} kullanıcısının kaydını onayladı.")
    flash('Kullanıcının hesabı onaylandı', 'success')
    return redirect(url_for('approve_users'))
    
@app.route('/admin/revoke/<int:id>')
@login_required
@admin_required
def revoke(id):
    user = db.session.get(User, id)
    if not user:
    	abort(404)
    if user.role == 'admin':
    	flash('Admin onayını kaldıramazsınız!', 'danger')
    	# Log kaydı ekle
    	log_action(db, Log, "Login", "Kullanıcı", current_user.id, f"{current_user.email} kullanıcısı {user.email} admin kullanıcısının onayını kaldırmayı denedi.")
    	return redirect(url_for('approve_users'))

    user.approved = False  # Kullanıcıyı onaysız yap
    db.session.commit()
    # Log kaydı ekle
    log_action(db, Log, "Login", "Kullanıcı", current_user.id, f"{current_user.email} admin kullanıcısı {user.email} kullanıcısının onayını kaldırdı.")
    flash('Kullanıcının onayı kaldırıldı.', 'warning')
    return redirect(url_for('approve_users'))
        
# Kullanıcı Çıkışı
@app.route('/logout')
@login_required
def logout():
    # Log kaydı ekle
    log_action(db, Log, "Login", "Kullanıcı", current_user.id, f"{current_user.email} kullanıcısı sistemden çıkış yaptı.")
    logout_user()  # session.clear() yerine bunu kullan
    session.clear()
    flash('Başarıyla çıkış yapıldı.', 'info')
    return redirect(url_for('login'))

# Giriş sayfası / Envanterler listesi
@app.route('/')
@app.route('/index')
@login_required
def index():
    all_items = Inventory.query.all() # Tüm envanterleri çek
    return render_template('index.html', items=all_items)

# Admin sayfası - yalnızca admin kullanıcılarına açık
@app.route('/admin')
@login_required
@admin_required
def admin():
    all_items = Inventory.query.all() # Tüm envanterleri çek
    return render_template('admin.html', items=all_items)

# Envanter ekleme sayfası
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        department = request.form['department']
        location = request.form['location']
        serial_number = request.form['serial_number']
        assigned_to = request.form['assigned_to']
        status = request.form['status']
        notes = request.form['notes']
        purchase_date = datetime.strptime(request.form['purchase_date'], "%Y-%m-%d").date()
        purchase_price = request.form['purchase_price']
        warranty_end = datetime.strptime(request.form['warranty_end'], "%Y-%m-%d").date()
        supplier = request.form['supplier']
        maintenance_required = request.form['maintenance_required']
        
        new_item = Inventory(
            name=name,
            category=category,
            department=department,
            location=location,
            serial_number=serial_number,
            status=status,
            notes=notes,
            purchase_date=purchase_date,
            purchase_price=purchase_price,
            warranty_end=warranty_end,
            supplier=supplier,
            maintenance_required=maintenance_required,
            assigned_to=assigned_to,
        )            
        db.session.add(new_item)
        db.session.commit()
        
        # Envanter resmi ekle
        imgfile = request.files['image']
        if imgfile:
            filename = secure_filename(imgfile.filename)
            file_ext = os.path.splitext(filename)[1]
            db.session.add(new_item)
            db.session.flush()  # new_item.id şimdi oluştu ama commit etmeden
            new_filename = f"resim_{new_item.id}{file_ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            imgfile.save(filepath)
            new_item.image_filename = new_filename
            db.session.commit()
        	
        # QR kod oluştur
        qr_filename = generate_qr_code(new_item.id)
        new_item.qrkod = qr_filename
        db.session.commit()
        
        # Log kaydı ekle
        log_action(db, Log, "Ekleme", "Envanter", new_item.id, f"{new_item.name} adlı envanteri {current_user.email} kullanıcısı ekledi.")
        
        flash("Yeni envanter başarıyla eklendi!", category='success')
        return redirect(url_for('index'))

    return render_template('item_add.html')
        
# Envanter düzenleme işlemi
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit(id):
    inventory = db.session.get(Inventory, id)  # Güncellenmek istenen demirbaş
    if not inventory:
    	abort(404)

    if request.method == 'POST':
        # Formdan gelen verilerle güncelleme yapıyoruz
        inventory.name = request.form['name']
        inventory.category = request.form['category']
        inventory.department = request.form['department']
        inventory.location = request.form['location']
        inventory.serial_number = request.form['serial_number']
        inventory.assigned_to = request.form['assigned_to']
        inventory.status = request.form['status']
        inventory.notes = request.form['notes']
        inventory.purchase_date = datetime.strptime(request.form['purchase_date'], "%Y-%m-%d").date()
        inventory.purchase_price = request.form['purchase_price']
        inventory.warranty_end = datetime.strptime(request.form['warranty_end'], "%Y-%m-%d").date()
        inventory.supplier = request.form['supplier']
        inventory.maintenance_required = request.form['maintenance_required']
        
        db.session.commit()  # Değişiklikleri veritabanına kaydediyoruz

        # Log kaydı ekle
        log_action(db, Log, "Düzenleme", "Envanter", inventory.id, f"{inventory.name} adlı envanteri {current_user.email} kullanıcısı düzenledi.")

        flash('Envanter başarıyla güncellendi!', 'success')
        return redirect(url_for('admin'))

    return render_template('item_edit.html', inventory=inventory)
    
# Envanter silme işlemi
@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete(id):
    inventory = db.session.get(Inventory, id)  # Silinecek demirbaş
    if not inventory:
    	abort(404)
    db.session.delete(inventory)
    db.session.commit()  # Veritabanından silme işlemini yapıyoruz
    
    # Log kaydı ekle
    log_action(db, Log, "Silme", "Envanter", inventory.id, f"{inventory.name} adlı envanteri {current_user.email} kullanıcısı sildi.")
 
    flash('Envanter başarıyla güncellendi!', 'success')
    return redirect(url_for('admin'))

# QR kodu oluşturma
def generate_qr_code(inventory_id):
    """Envanterin detay sayfasına yönlendiren QR kod oluşturur."""
    host = request.host  # kullanıcının eriştiği host bilgisi (127.0.0.1:5000 debug için)
    qr_url = f"http://{host}/item/{inventory_id}" # !!!IP adresi değiştiğinde QR kodları çalışmaz hale gelir!!!!
    qr = qrcode.make(qr_url)
    qr_filename = f"qr_{inventory_id}.png"
    qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
    qr.save(qr_path)
    return qr_filename

# QR kodunu yenileme
@app.route('/regenerate_qr_code/<int:item_id>')
@login_required
@admin_required
def regenerate_qr_code(item_id):
	item = db.session.get(Inventory, item_id)
	qr_filename = generate_qr_code(item.id)
	item.qrkod = qr_filename
	db.session.commit()
	
	# Log kaydı ekle
	log_action(db, Log, "Düzenleme", "Envanter", item.id, f"{item.name} adlı envanterin QR kodu {current_user.email} kullanıcısı tarafından yeniden oluşturuldu.")
	
	flash("Envanter QR kodu başarıyla güncellendi!", category='success')
	return redirect(url_for('item_details', id=item.id))
            
# QR kodu görseli indirme
@app.route('/download_qr_code/<int:item_id>')
def download_qr_code(item_id):
    item = db.session.get(Inventory, item_id)
    if not item:
    	abort(404)
    qr_image = os.path.join(app.config['UPLOAD_FOLDER'], item.qrkod)
    return send_file(qr_image, mimetype='image/png', as_attachment=True, download_name=f"qr_{item_id}.png")
    
# Envanteri kullanıcıya zimmetle
@app.route('/assign/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def assign(item_id):
	item = db.session.get(Inventory, item_id)
	item_was_assigned_to = item.assigned_to
	if not item:
		abort(404)
	item.assigned_to = request.form.get('assign_to')
	db.session.commit()
	
	# Log kaydı ekle
	log_action(db, Log, "Düzenleme", "Envanter", item.id, f"{item.name} adlı envanteri {current_user.email} kullanıcısı {item_was_assigned_to} kullanıcından {item.assigned_to} kullanıcısına zimmetledi.")
	
	flash("Envanter başarıyla zimmetlendi!", category='success')
	return redirect(url_for('index'))
    
# Spesifik envanter detaylarını göster
@app.route('/item/<int:id>')
@login_required
def item_details(id):
    item = db.session.get(Inventory, id)
    if not item:
    	abort(404)
    return render_template('item_details.html', item=item)

@app.route('/logs')
@login_required
@admin_required
def view_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    uploads_dir = os.path.join(current_app.instance_path, 'uploads')
    return send_from_directory(uploads_dir, filename)
        
# Restrict Access to Local Network
if __name__ == '__main__':
    app.run()#debug=True, host='0.0.0.0', port=5000)
