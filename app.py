from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Secret key for sessions and CSRF protection
app.config['SECRET_KEY'] = 'your_secret_key'

# Database setup (SQLite for simplicity)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    posts = db.relationship('ServicePost', backref='author', lazy=True)

# Define ServicePost model
class ServicePost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<ServicePost {self.title}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already registered. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Registration successful!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    # Query all posts by the logged-in user
    posts = ServicePost.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', posts=posts)

@app.route('/university')
def university():
    return render_template('university.html')

@app.route('/highschool')
def highschool():
    return render_template('highschool.html')

@app.route('/supply')
def supply():
    # Query all services from the database
    services = ServicePost.query.all()
    return render_template('supply.html', services=services)

# Route for individual service pages
@app.route('/service/<int:service_id>')
def service_detail(service_id):
    service = ServicePost.query.get_or_404(service_id)
    return render_template('service_detail.html', service=service)

# Route to handle the form submission for posting a service
@app.route('/add_service', methods=['POST'])
@login_required
def add_service():
    title = request.form['title']
    description = request.form['description']
    category = request.form['category']
    price = float(request.form['price'])

    new_post = ServicePost(title=title, description=description, category=category, price=price, author=current_user)
    db.session.add(new_post)
    db.session.commit()
    return redirect(url_for('supply'))

# Route for deleting a post
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = ServicePost.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)  # Prevents deletion if the current user is not the author
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('profile'))

# Route for searching services
@app.route('/search_results', methods=['GET'])
def search_results():
    category = request.args.get('category')
    results = ServicePost.query.filter(ServicePost.category.like(f"%{category}%")).all()
    return render_template('search_results.html', results=results)

if __name__ == "__main__":
    # Create the database tables if they don't exist yet
    with app.app_context():
        db.create_all()
    app.run(debug=True)
