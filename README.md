# Envanter Takip Uygulaması

Basit bir Flask tabanlı envanter takip sistemi. QR kod üretme, filtreleme, dışa aktarma gibi özellikler içerir.

## Kurulum

```bash
git clone https://github.com/sinansagir/flask-inventory-app.git
cd flask-inventory-app
python -m venv venv
venv\Scripts\activate  # Windows için
source venv/bin/activate  # MacOS için
pip install -r requirements.txt
export FLASK_APP=app.py
flask db init  # Sadece ilk kez yapılır
flask db migrate -m "initial migration"
flask db upgrade