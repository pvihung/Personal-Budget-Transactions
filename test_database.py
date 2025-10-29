from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import Table
from sqlalchemy import Column, Integer, String, Numeric, DATETIME, Boolean, ForeignKey

# Creating a database (SQLite for simplicity)
engine = create_engine("sqlite:///Univ.db") #the sqlite tells that we are going to use it as our database.
#If we want to use mysql or anyother database then replace sqlite with it

# Base class for ORM models
Base = declarative_base()

class User(Base):
    __tablename__ = "user_details"

    user_id = Column(Integer, primary_key=True) #household_id
    user_name = Column(String, nullable=False)
    password = Column(String, nullable=False)


class Transaction(Base):
    __tablename__ = "transaction_details"

    transaction_id = Column(Integer, primary_key=True)
    record_type = Column(String, nullable=False)
    transaction_date = Column(DATETIME, nullable=False)
    amount = Column(Numeric(18,2), nullable=False)
    category = Column(String, nullable=False)
    is_recurring = Column(Boolean, nullable=False)
    recurrence_level = Column(String, nullable=False)

    user_transactions = relationship("UserTransaction", back_populates="transaction")

# Add a relationship in Student
User.transaction = relationship("Transaction", back_populates="user_transactions", cascade="all, delete")

# Create tables
Base.metadata.create_all(engine)


