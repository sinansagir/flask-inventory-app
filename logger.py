import logging
from datetime import datetime
from flask_login import current_user

# Log yapılandırması
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def log_action(db, Log, action, entity_type, entity_id, details=""):
    """
    Log kaydını hem veritabanına hem de dosyaya ekler.

    :param action: Yapılan işlem türü (Ekleme, Güncelleme, Silme, Onaylama vs.)
    :param entity_type: İşlem yapılan nesne türü (User, Inventory, Admin vs.)
    :param entity_id: İşlem yapılan nesnenin ID'si
    :param details: Ekstra açıklama (isteğe bağlı)
    """
    user_id = current_user.id if current_user.is_authenticated else None
    user_email = current_user.email if current_user.is_authenticated else None
    timestamp = datetime.utcnow()

    # Log verisini veritabanına kaydet
    new_log = Log(
        user_id=user_id,
        user_email=user_email,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        timestamp=timestamp,
    )
    db.session.add(new_log)
    db.session.commit()

    # Log dosyasına yaz
    log_message = f"[{timestamp}] {action} - {entity_type} ID: {entity_id} - User: {user_email} - {details}"
    logging.info(log_message)
