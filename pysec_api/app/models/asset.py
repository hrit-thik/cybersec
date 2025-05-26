from datetime import datetime
from . import db # Assuming db will be initialized in app/models/__init__.py

class Asset(db.Model):
    __tablename__ = 'asset' # Explicitly set table name

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    url = db.Column(db.String(255), nullable=False) # Assuming URL can be long
    
    total_findings = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    prioritized_findings = db.Column(db.Integer, default=0)
    
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # The 'user' table name for ForeignKey comes from User model's __tablename__ or default Flask-SQLAlchemy naming.
    # If User model uses __tablename__ = 'users', then 'users.id'. Assuming 'user.id' for now.
    
    user = db.relationship('User', backref=db.backref('assets', lazy=True))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Asset {self.name}>'
