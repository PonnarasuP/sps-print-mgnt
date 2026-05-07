import sqlite3

DB_PATH = 'instance/sublimation_jobs.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Check if 'history' column exists
c.execute("PRAGMA table_info(job)")
columns = [row[1] for row in c.fetchall()]

if 'history' not in columns:
    c.execute("ALTER TABLE job ADD COLUMN history TEXT DEFAULT '';")
    print("Column 'history' added.")
else:
    print("Column 'history' already exists.")

conn.commit()
conn.close()
