from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os

Base = declarative_base()

class Website(Base):
    __tablename__ = 'websites'

    id = Column(Integer, primary_key=True)
    url = Column(String(255), unique=True, nullable=False)
    status = Column(String(20), default='pending')
    pages = relationship('Page', back_populates='website')

class Page(Base):
    __tablename__ = 'pages'

    id = Column(Integer, primary_key=True)
    url = Column(String(255), unique=True, nullable=False)
    content = Column(Text)
    website_id = Column(Integer, ForeignKey('websites.id'))
    website = relationship('Website', back_populates='pages')

DATABASE_URL = os.environ.get('DATABASE_URL')
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)