from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import Column, Integer, String, Numeric, ForeignKey

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
    transaction_date = Column(String, nullable=False)
    payment_method = Column(String, nullable=False)

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

# Create tables (no-op if already present)
Base.metadata.create_all(engine)

# Session factory
Session = sessionmaker(bind=engine)


# Since we only use the database structure,
# this will only run to check if the databases are created properly
if __name__ == '__main__':
    # Import final_records here to avoid heavy IO on import
    from Database.dataframe import final_records, final_user

    session = Session()
    try:
        user_rows = final_user.to_dict(orient='records')
        for row in user_rows:
            user = User(**row)
            session.add(user)
        session.commit()
        print(f'{len(user_rows)} users added to database')

        record_rows = final_records.to_dict(orient='records')
        for row in record_rows:
            record = Record(**row)
            session.add(record)
        session.commit()
        print(f'{len(record_rows)} records added to database')
    except Exception as e:
        print('Error:', e)
        session.rollback()
    finally:
        session.close()