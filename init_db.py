import sqlite3
from werkzeug.security import generate_password_hash
password = generate_password_hash("1234")
def connect_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def create_db():
    db = connect_db()
    c = db.cursor()
    c.execute('''
   CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT NOT NULL UNIQUE,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,            
        result TEXT,                    
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')    
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS crypto_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cipher_type TEXT NOT NULL,
            operation TEXT NOT NULL,
            input_text TEXT,
            result TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS social_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scenario TEXT NOT NULL,           
            input_text TEXT,                  
            result TEXT,                  
            score INTEGER DEFAULT 0,          
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS dirsearch_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        wordlist TEXT,                    
        result TEXT,                      
        found_count INTEGER DEFAULT 0,   
        status_codes TEXT,                
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
''')
    c.execute(
    " INSERT INTO users (login, first_name, last_name, email, password, role) "
    "VALUES (?, ?, ?, ?, ?, ?)",
    ('admin', 'Admin', 'Adminov', 'admin@astanait.edu.kz', password, 'admin')
        

)
    
    db.commit()
    db.close()

create_db()