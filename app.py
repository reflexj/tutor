from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

# Secret key for sessions and CSRF protection
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///students.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialize Flask-Migrations
migrate = Migrate(app, db)

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    posts = db.relationship('ServicePost', backref='user', lazy=True)

# Define ServicePost model (University Student Services)
class ServicePost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    university = db.Column(db.String(100), nullable=False)
    semester = db.Column(db.String(50), nullable=False)
    contact =db.Column(db.String(100), nullable = False)
    additional_info =db.Column(db.String(200), nullable = True)
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
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))



@app.route('/university')
def university():
    return render_template('university.html')

@app.route('/highschool')
def highschool():
    return render_template('highschool.html')

@app.route('/supply')
def supply():
    # Fetch all the service posts
    posts = ServicePost.query.all()
    return render_template('supply.html', posts=posts)


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
    price = float(request.form['price'])
    subject = request.form['subject']
    university = request.form['university']
    semester = request.form['semester']
    contact = request.form['contact']
    additional_info = request.form.get('additional_info')


    new_post = ServicePost(
        title=title, 
        description=description, 
        price=price, 
        subject=subject, 
        university=university,
        semester=semester,
        contact = contact,
        additional_info = additional_info,
        user=current_user
    )
    db.session.add(new_post)
    db.session.commit()
    return redirect(url_for('supply'))

# Route for deleting a post
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = ServicePost.query.get_or_404(post_id)
    if post.user != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('profile'))

# Route for searching services
@app.route('/search_results_supply', methods=['GET'])
def search_results_supply():
    query = request.args.get('query')  # Get the search term from the URL (query parameter)
    
    if query:
        results = ServicePost.query.filter(
            (ServicePost.title.ilike(f"%{query}%")) |  # Match title
            (ServicePost.subject.ilike(f"%{query}%"))  # Or match subject
        ).all()
    else:
        results = ServicePost.query.all()  # If no query, show all results
    
    return render_template('search_results_supply.html', results=results)



#Demand side Deletable if need 

class RequestPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    price = db.Column(db.String(100), nullable=False)
    additional_information = db.Column(db.String(200), nullable=True)
    contact =db.Column(db.String(100), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('requests', lazy=True))

    def __repr__(self):
        return f'<RequestPost {self.title}>'


@app.route('/add_demand', methods=['POST'])
@login_required
def add_demand():
    title = request.form['title']
    description = request.form['description']
    subject = request.form['subject']
    price = request.form.get('price')
    contact = request.form.get('contact')
    additional_information = request.form.get('additional_info')

    new_request = RequestPost(
        title=title,
        description=description,
        subject=subject,
        price=price,
        contact=contact,
        additional_information=additional_information,
        user_id=current_user.id
    )

    db.session.add(new_request)
    db.session.commit()

    flash('Your request has been submitted successfully!', 'success')
    return redirect(url_for('requests'))



@app.route('/requests')
def requests():
    requests = RequestPost.query.all()  # Get all the requests
    return render_template('requests.html', requests=requests)


@app.route('/delete_request/<int:request_id>', methods=['POST'])
@login_required
def delete_request(request_id):
    request_post = RequestPost.query.get_or_404(request_id)
    
    # Ensure the current user is the owner of the post
    if request_post.user_id == current_user.id:
        db.session.delete(request_post)
        db.session.commit()
    
    return redirect(url_for('profile'))

@app.route('/request/<int:request_id>')
def request_detail(request_id):
    request_post = RequestPost.query.get_or_404(request_id)
    return render_template('request_detail.html', request=request_post)

@app.route('/search_results_requests', methods=['GET'])
def search_results_requests():
    query = request.args.get('query')
    if query:
        results = RequestPost.query.filter(
            (RequestPost.title.ilike(f"%{query}%")) |
            (RequestPost.subject.ilike(f"%{query}%"))
        ).all()
    else:
        results = RequestPost.query.all()
    
    return render_template('search_results_requests.html', results=results)



#demandside until here

@app.route('/profile')
@login_required
def profile():
    service_posts = ServicePost.query.filter_by(user_id=current_user.id).all()
    request_posts = RequestPost.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', service_posts=service_posts, request_posts=request_posts)

if __name__ == "__main__":
    app.run(debug=True)
