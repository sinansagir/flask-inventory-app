from app import app, db, User  # app objesini de içe aktar
from werkzeug.security import generate_password_hash
import sys

def create_admin(email, password):
    """Yeni bir admin kullanıcısı oluşturur"""
    with app.app_context():  # App context açılıyor
        if User.query.filter_by(email=email).first():
            print("Bu email ile zaten bir kullanıcı var.")
            return
        admin = User(
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            role="admin",
            approved=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin başarıyla oluşturuldu! Email: {email}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Kullanım: python create_admin.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]

    create_admin(email, password)
