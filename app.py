from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS user_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    favorite BOOLEAN DEFAULT 0,
                    done BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')

    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'ADMIN123', 'adminadmin')")

    conn.commit()
    conn.close()

def query_db(query, args=(), one=False):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute(query, args)
    rv = c.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/')
def index():
    return render_template('login_register.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    try:
        query_db("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        flash('Registration successful! Please log in.', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists.', 'danger')

    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = query_db("SELECT * FROM users WHERE username = ? AND password = ?", (username, password), one=True)

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        if user[1] == 'ADMIN123':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        flash('Invalid credentials.', 'danger')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session['username'] == 'ADMIN123':
        return redirect(url_for('index'))

    user_data = query_db("SELECT * FROM user_data WHERE user_id = ?", (session['user_id'],))
    return render_template('dashboard.html', user_data=user_data)

@app.route('/add_data', methods=['POST'])
def add_data():
    if 'user_id' in session:
        data = request.form['data']
        query_db("INSERT INTO user_data (user_id, data) VALUES (?, ?)", (session['user_id'], data))
        flash('Data added successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/toggle/<int:data_id>/<action>')
def toggle_action(data_id, action):
    if action == 'favorite':
        query_db("UPDATE user_data SET favorite = NOT favorite WHERE id = ?", (data_id,))
    elif action == 'done':
        query_db("UPDATE user_data SET done = NOT done WHERE id = ?", (data_id,))
    return redirect(url_for('dashboard'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['username'] != 'ADMIN123':
        return redirect(url_for('index'))

    users = query_db("SELECT id, username FROM users WHERE username != 'ADMIN123'")
    return render_template('admin_dashboard.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    username = request.form['username']
    password = request.form['password']
    query_db("UPDATE users SET username = ?, password = ? WHERE id = ?", (username, password, user_id))
    flash('User updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_item/<int:data_id>', methods=['GET'])
def delete_item(data_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    query_db("DELETE FROM user_data WHERE id = ?", (data_id,))
    flash('Item deleted successfully!', 'success')
    
    return redirect(url_for('dashboard'))


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    query_db("DELETE FROM users WHERE id = ?", (user_id,))
    query_db("DELETE FROM user_data WHERE user_id = ?", (user_id,))
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
