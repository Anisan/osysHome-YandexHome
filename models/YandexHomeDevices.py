from app.database import Column, Model, SurrogatePK, db

class Device(SurrogatePK, db.Model):
    __tablename__ = 'yandexhome_devices'
    title = Column(db.String(50))
    type = Column(db.String(50))
    room = Column(db.String(50))
    description = Column(db.String(100))
    manufacturer = Column(db.String(50))
    model = Column(db.String(50))
    sw_version = Column(db.String(50))
    hw_version = Column(db.String(50))
    capability = Column(db.Text)
    config = Column(db.Text)
