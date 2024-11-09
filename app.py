from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Secret key for sessions and CSRF protection
app.config['SECRET_KEY'] = 'your_secret_key'

# Database setup (SQLite for simplicity)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define models (for user and service posts)
class ServicePost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<ServicePost {self.title}>'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/university')
def university():
    return render_template('university.html')

@app.route('/highschool')
def highschool():
    return render_template('highschool.html')

# Route to handle the form submission for posting a service
@app.route('/add_service', methods=['POST'])
def add_service():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        price = float(request.form['price'])

        new_post = ServicePost(title=title, description=description, category=category, price=price)

        try:
            db.session.add(new_post)
            db.session.commit()
            return redirect('/university')  # Redirect back to the university page after submission
        except Exception as e:
            return f"Error: {e}"

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
