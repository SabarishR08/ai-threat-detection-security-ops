import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

# Path to your SQLite database
DB_PATH = os.getenv("DATABASE_URL", "database/threats.db").replace("sqlite:///", "")

def clear_db():
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        return

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # Clear the existing tables that exist
        tables = ["threats", "blacklisted_ips"]
        for table in tables:
            try:
                cursor.execute(f"DELETE FROM {table};")
                print(f"✅ Cleared table: {table}")
            except sqlite3.OperationalError:
                print(f"⚠ Table does not exist: {table}")
        conn.commit()

    print("🎉 All existing tables cleared successfully!")

if __name__ == "__main__":
    clear_db()
