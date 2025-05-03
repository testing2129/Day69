from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from werkzeug.security import generate_password_hash, check_password_hash
import datetime as dt
from bs4 import BeautifulSoup
from post import Post
import requests
import re
import secrets
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user,
)
from sqlalchemy.orm import relationship
from functools import wraps

recipient = "gabriel.janvrin@gmail.com"
sender = "philippe.janvrin@laposte.net"
password = "Antosia,071116"


year = dt.datetime.now().year
month = dt.datetime.now().strftime("%B")
day = dt.datetime.now().day

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["WTF_CSRF_SECRET_KEY"] = secrets.token_hex(32)
csrf = CSRFProtect(app)
bootstrap = Bootstrap(app)  # Properly initialize Bootstrap with app instance

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_required(f):
    """Decorator to check if the user is an admin."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(403)  # Forbidden
        if "admin" not in current_user.roles.split(","):
            abort(403)  # Forbidden
        return f(*args, **kwargs)

    return decorated_function


# Connect to Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///articles.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

app.config["CKEDITOR_PKG_TYPE"] = "basic"
ckeditor = CKEditor(app)


# Define the Article model
class Article(db.Model):
    __tablename__ = "article"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    link = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    views = db.Column(db.Integer, default=0)
    date = db.Column(db.DateTime, default=dt.datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Create reference to the User object, the "articles" refers to the articles property in the User class
    author = relationship("User", back_populates="articles")
    # Create reference to the Comment object
    comments = relationship("Comment", back_populates="article", cascade="all, delete")

    def to_dict(self):
        return {
            column.name: getattr(self, column.name) for column in self.__table__.columns
        }


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    roles = db.Column(
        db.String(200), default="user"
    )  # Allow multiple roles as a comma-separated string
    # Create back_populates to Article object with cascade delete
    articles = relationship("Article", back_populates="author", cascade="all, delete")
    # Create back_populates to Comment object
    comments = relationship("Comment", back_populates="author", cascade="all, delete")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey("article.id"), nullable=False)
    date = db.Column(db.DateTime, default=dt.datetime.utcnow)
    # Create reference to the User object
    author = relationship("User", back_populates="comments")
    # Create reference to the Article object
    article = relationship("Article", back_populates="comments")


def fetch_top_articles(url="https://news.ycombinator.com/", n=5):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching articles: {e}")
        return []
    soup = BeautifulSoup(response.text, "html.parser")

    articles_data = [
        (
            article.getText(),
            article.find("a").get("href") if article.find("a") else None,
        )
        for article in soup.find_all(name="span", class_="titleline")
    ]
    article_upvotes = [
        int(score.getText().split()[0])
        for score in soup.find_all(name="span", class_="score")
    ]

    top_indices = sorted(
        range(len(article_upvotes)), key=lambda i: article_upvotes[i], reverse=True
    )[:n]

    top_articles = []
    for i in top_indices:
        title = articles_data[i][0]
        link = articles_data[i][1]
        upvotes = article_upvotes[i]
        top_articles.append({"title": title, "link": link, "upvotes": upvotes})

    all_articles = []
    for article in top_articles:
        title = article["title"]
        match = re.search(r"\((.*?\..*?)\)", title)
        if match:
            extracted_content = match.group(1)
            cleaned_title = title.replace(f"({extracted_content})", "").strip()
            article["title"] = cleaned_title
            article["content"] = extracted_content
        all_articles.append(article)
    return all_articles


@app.route("/")
def home():
    # Get all articles from database
    top_articles = db.session.execute(db.select(Article)).scalars().all()

    # If database is empty, fetch and store new articles
    if not top_articles:
        # Get the first admin user to set as author for fetched articles
        admin_user = db.session.execute(
            db.select(User).filter_by(roles="admin")
        ).scalar_one_or_none()

        if not admin_user:
            flash("No admin user found. Please register an admin user first.", "error")
            return redirect(url_for("register"))

        fetched_articles = fetch_top_articles()
        for article in fetched_articles:
            new_article = Article(
                title=article["title"],
                link=article["link"],
                content=article.get("extracted_content", ""),
                views=article.get("upvotes", 0),
                date=dt.datetime.now(dt.timezone.utc),
                author=admin_user,  # Set the admin user as the author
            )
            db.session.add(new_article)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("Error saving fetched articles", "error")
            return redirect(url_for("home"))

        top_articles = db.session.execute(db.select(Article)).scalars().all()

    return render_template(
        "index.html",
        articles=top_articles,  # Pass the full article objects to template
        current_year=year,
        current_month=month,
        rand_day=day,
    )


@app.route("/post/<int:index>", methods=["GET", "POST"])
def show_post(index):
    # Get article from database
    articles = db.session.execute(db.select(Article)).scalars().all()
    if not articles or index >= len(articles):
        abort(404)  # Not Found

    article = articles[index]
    # Increment view count
    article.views += 1
    db.session.commit()

    # Create Post object for template
    post = Post(title=article.title, link=article.link, upvotes=article.views)
    post.content = article.content
    post.date = article.date
    post.author = article.author.name if article.author is not None else "Unknown"
    if not post.content:
        post.fetch_content()
        article.content = post.content
        db.session.commit()

    # Handle comment form
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to log in to comment.", "error")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            article=article,
            author=current_user,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", index=index))

    return render_template(
        "post.html",
        post=post,
        current_year=year,
        current_month=month,
        rand_day=day,
        index=index,
        form=form,
        article=article,  # Pass the article object to access comments
    )


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_required
def create_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = Article(
            title=form.title.data,
            link=form.link.data,
            content=form.content.data,
            views=0,
            date=dt.datetime.now(dt.timezone.utc),
            author=current_user,  # Add the current user as the author
        )
        db.session.add(new_post)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            return render_template(
                "new_post.html",
                form=form,
                error="An error occurred while creating the post.",
            )
        # Fetch content from the link if not provided
        if not new_post.content:
            post = Post(
                title=new_post.title, link=new_post.link, upvotes=0, date=new_post.date
            )
            post.fetch_content()
            new_post.content = post.content
            db.session.commit()
        # Redirect to the new post page
        return redirect(url_for("home"))
    return render_template(
        "new_post.html",
        form=form,
        new_post=True,
    )


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_post(post_id):
    # Get all articles and edit by index position
    articles = db.session.execute(db.select(Article)).scalars().all()
    if not articles or post_id >= len(articles):
        abort(404)  # Not Found

    post = articles[post_id]  # Get the article at the index position
    edit_form = CreatePostForm(
        title=post.title,
        link=post.link,
        content=post.content,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.link = edit_form.link.data
        post.content = edit_form.content.data
        db.session.commit()
        return redirect(url_for("show_post", index=post_id))
    return render_template("new_post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    # Query the article directly by its ID
    article = Article.query.get(post_id)
    if not article:
        flash("Post not found", "error")
        return redirect(url_for("home"))

    # Check if user is authorized to delete this post
    if current_user.id != article.author_id and current_user.roles != "admin":
        abort(403)  # Forbidden

    db.session.delete(article)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash("Error deleting post", "error")
    return redirect(url_for("home"))


@app.route("/old")
def show_old_home():
    return render_template(
        "old_index.html",
        current_year=year,
        current_month=month,
        rand_day=day,
    )


@app.route("/old/post/<int:index>")
def show_old_posts(index):
    return render_template(
        "old_posts.html",
        current_year=year,
        current_month=month,
        rand_day=day,
        index=index,
    )


@app.route("/about")
def about():
    return render_template("about.html", current_year=year)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data

        if not email or not password or not name:
            flash("Please fill out all fields.", "error")
            return render_template("register.html", form=form)

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("register.html", form=form)

        if db.session.query(User).count() == 0:
            new_user = User(
                email=email,
                password=generate_password_hash(
                    password, method="pbkdf2:sha256", salt_length=8
                ),
                name=name,
                roles="admin",
            )
        else:
            if User.query.filter_by(email=email).first():
                flash(
                    "Email already registered. Please proceed to the log in page.",
                    "error",
                )
                return redirect(url_for("login"))
            else:
                new_user = User(
                    email=email,
                    password=generate_password_hash(
                        password, method="pbkdf2:sha256", salt_length=8
                    ),
                    name=name,
                )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash("Registration successful!", "success")
        return redirect(url_for("home"))
    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        return redirect(url_for("home"))

    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials. Please try again.", "error")
            return render_template("login.html", form=login_form)

    return render_template("login.html", form=login_form)


@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden_error(error):
    return render_template("403.html"), 403


@app.errorhandler(401)
def unauthorized_error(error):
    return render_template("401.html"), 401


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
