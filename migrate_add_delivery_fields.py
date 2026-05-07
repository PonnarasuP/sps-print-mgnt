import sqlite3

DB_PATH = 'instance/sublimation_jobs.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()


def add_column(name, type_):
    c.execute("PRAGMA table_info(job)")
    columns = [row[1] for row in c.fetchall()]
    if name not in columns:
        c.execute(f"ALTER TABLE job ADD COLUMN {name} {type_}")
        print(f"Column '{name}' added.")
    else:
        print(f"Column '{name}' already exists.")


add_column('delivery_method', 'TEXT')
add_column('delivery_details', 'TEXT')

conn.commit()
conn.close()
print('Delivery fields migration complete.')
