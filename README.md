# Envanter Takip Uygulaması

Basit bir Flask tabanlı envanter takip sistemi. QR kod üretme, filtreleme, dışa aktarma gibi özellikler içerir.

## Kurulum MacOS

```bash
git clone https://github.com/sinansagir/flask-inventory-app.git
cd flask-inventory-app
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.py
flask db init  # Sadece ilk kez yapılır
flask db migrate -m "initial migration"
flask db upgrade```

## Kurulum Windows

```bash
git clone https://github.com/sinansagir/flask-inventory-app.git 
cd flask-inventory-app
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
set FLASK_APP=app.py
set FLASK_ENV=development
flask db init  # Sadece ilk kez yapılır
flask db migrate -m "initial migration"
flask db upgrade```