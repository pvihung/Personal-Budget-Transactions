from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.sql import func
from sqlalchemy import Column, Integer, String, Numeric, DATETIME, Boolean, ForeignKey

# Import data
from Database.dataframe import final_df, final_records

# Creating a database (SQLite for simplicity)
engine = create_engine("sqlite:///App.db")

# Base class for ORM models
Base = declarative_base()

class Record(Base):
    __tablename__ = "records"

    record_id = Column(Integer, primary_key=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    record_type = Column(String, nullable=False)
    category = Column(String, nullable=False)
    amount = Column(Numeric(10,2), nullable=False)
    currency = Column(String)
    transaction_date = Column(DATETIME, nullable=False)
    payment_method = Column(String, nullable=False)
    is_recurring = Column(Boolean, nullable=False)
    recurrence_interval = Column(String, nullable=False)

    user = relationship("User", back_populates="records")

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, nullable=False)
    user_name = Column(String, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, nullable=True)
    household_size = Column(Integer, nullable=True)
    location_city = Column(String, nullable=True)
    location_state = Column(String, nullable=True)
    location_postal_code = Column(String, nullable=True)
    location_country = Column(String, nullable=True)

    records = relationship("Record", back_populates="user")

# Create tables
Base.metadata.create_all(engine)

# Importing all data into databases
Session = sessionmaker(bind=engine)
session = Session()

try:
    rows = final_records.to_dict(orient='records')
    for row in rows:
        record = Record(**row)
        session.add(record)
    session.commit()
    print(f'{len(rows)} records added to database')
except Exception as e:
    print('Error:', e)
    session.rollback()

