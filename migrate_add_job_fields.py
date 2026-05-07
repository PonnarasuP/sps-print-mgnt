import sqlite3

DB_PATH = 'instance/sublimation_jobs.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Add new columns if they do not exist
def add_column(name, type_):
    c.execute("PRAGMA table_info(job)")
    columns = [row[1] for row in c.fetchall()]
    if name not in columns:
        c.execute(f"ALTER TABLE job ADD COLUMN {name} {type_}")
        print(f"Column '{name}' added.")
    else:
        print(f"Column '{name}' already exists.")

add_column('rip_format', 'TEXT')
add_column('size', 'TEXT')
add_column('qty', 'INTEGER')
add_column('no_of_meter', 'REAL')
add_column('size_of_roll', 'TEXT')
add_column('ink', 'TEXT')
add_column('start_time', 'TEXT')
add_column('end_time', 'TEXT')

conn.commit()
conn.close()
print('Migration complete.')
