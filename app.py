
from flask import Flask, redirect, request, session, render_template
from google_auth_oauthlib.flow import Flow
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from flask import request, redirect, url_for, flash
from psycopg2.extras import RealDictCursor


# =============================
# 初期設定
# =============================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_SECRETS_FILE = "client_secret.json"
DATABASE_URL = os.environ["DATABASE_URL"]

# =============================
# DB 接続関数
# =============================
def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.DictCursor
    )

# =============================
# DB 初期化
# =============================
def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            name TEXT,
            google_login BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

# =============================
# ページ
# =============================
@app.route("/")
def title_page():
    return render_template("title.html")

# =============================
# サインアップ
# =============================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_pw)
            )
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return "そのメールアドレスはすでに登録されています"
        finally:
            cur.close()
            conn.close()

        return redirect("/signin")

    return render_template("signup.html")

# =============================
# サインイン
# =============================
@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password FROM users WHERE email = %s",
            (email,)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and user["password"] and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect("/select")
        else:
            return "メールアドレスまたはパスワードが違います"

    return render_template("signin.html")

# =============================
# Email サインイン（signup_email.html 用）
# =============================
def get_db_connection():
    return psycopg2.connect(
        os.environ["DATABASE_URL"],
        sslmode="require"
    )

@app.route("/signup-email", methods=["GET", "POST"])
def signup_email():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO users (email, password)
                VALUES (%s, %s)
                """,
                (email, password_hash),
            )

            conn.commit()
            cur.close()
            conn.close()

            return redirect(url_for("difficulty"))  # 次の画面へ

        except psycopg2.errors.UniqueViolation:
            flash("This email is already registered.")
            return redirect(url_for("signup_email"))

        except Exception as e:
            print(e)
            flash("Something went wrong.")
            return redirect(url_for("signup_email"))

    return render_template("signup_email.html")


# =============================
# パスワード忘れ
# =============================
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]
        return f"パスワードリセット（未実装）: {email}"

    return render_template("forgot.html")

# =============================
# Google ログイン
# =============================
@app.route("/auth/google")
def auth_google():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        redirect_uri="http://localhost:8000/auth/google/callback"
    )

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/auth/google/callback")
def google_callback():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid"
        ],
        redirect_uri="http://localhost:8000/auth/google/callback"
    )

    flow.fetch_token(authorization_response=request.url)

    from google.oauth2 import id_token
    from google.auth.transport import requests

    id_info = id_token.verify_oauth2_token(
        flow.credentials._id_token,
        requests.Request(),
        audience=flow.client_config["client_id"]
    )

    email = id_info["email"]
    name = id_info.get("name", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user:
        cur.execute(
            "INSERT INTO users (email, name, google_login) VALUES (%s, %s, TRUE) RETURNING id",
            (email, name)
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
    else:
        user_id = user["id"]

    cur.close()
    conn.close()

    session["user_id"] = user_id
    return redirect("/select")

# =============================
# ログアウト
# =============================
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect("/signin")

# =============================
# 選択・問題画面
# =============================
@app.route("/difficulty")
def difficulty():
    return render_template("difficulty.html")

@app.route("/frequency")
def frequency():
    return render_template("frequency.html")

@app.route("/ready")
def ready():
    return render_template("ready.html")

@app.route("/select")
def select():
    return render_template("select.html")

def level_to_int(level):
    return {
        "Easy": 1,
        "Normal": 2,
        "Difficult": 3
    }.get(level)

@app.route("/question", methods=["GET", "POST"])
def question():
    genre_en = request.args.get("genre")
    level = request.args.get("level")
    reset = request.args.get("reset")

    if not genre_en or not level:
        return "パラメータが不足しています"

    if reset == "1":
        session.clear()

    level_map = {
        "Easy": 1,
        "Normal": 2,
        "Difficult": 3
    }
    difficulty = level_map.get(level)
    if difficulty is None:
        return "不正なレベルです"

    # =========================
    # 初期化
    # =========================
    if "used_question_ids" not in session:
        session["used_question_ids"] = []
        session["question_count"] = 0
        session["correct_count"] = 0

    # =========================
    # POST（Next）
    # =========================
    if request.method == "POST":
        question_id = int(request.form.get("question_id"))
        is_correct = request.form.get("is_correct")

        session["used_question_ids"].append(question_id)
        session["question_count"] += 1
        
        if is_correct == "1":
            session["correct_count"] += 1

        return redirect(url_for("question", genre=genre_en, level=level))

    conn = get_db_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:

        # =========================
        # 残り問題チェック
        # =========================
        cur.execute("""
            SELECT
                q.id,
                q.question_text,
                q.explanation,
                c.name AS category_name,
                ci.image_data
            FROM quiz_questions q
            JOIN quiz_categories c 
                ON q.category_id = c.id
            LEFT JOIN category_images ci
                ON ci.category_id = c.id
            WHERE c.name_en = %s
                AND q.difficulty = %s
                AND q.id NOT IN %s
            ORDER BY q.id
            LIMIT 1
        """, (
            genre_en,
            difficulty,
            tuple(session["used_question_ids"]) or (0,)
        ))

        question = cur.fetchone()

        if not question:
            total = session.get("question_count", 0)
            correct = session.get("correct_count", 0)

            #session.clear()

            return render_template(
                "question.html",
                finished=True,
                total=total,
                correct=correct,
                genre=genre_en,
                level=level
            )

        # 選択肢
        cur.execute("""
            SELECT id, choice_text, is_correct
            FROM quiz_choices
            WHERE question_id = %s
            ORDER BY id
        """, (question["id"],))
        choices = cur.fetchall()

    correct_choice_id = next(c["id"] for c in choices if c["is_correct"])

    return render_template(
        "question.html",
        finished=False,
        question={
            "id": question["id"],
            "number": session["question_count"] + 1,
            "question_text": question["question_text"],
            "correct_choice_id": correct_choice_id,
            "explanation": question["explanation"],
            "image_url": question["image_data"],
            "correct_choice_id": correct_choice_id
        },
        choices=choices,
        genre=genre_en,
        level=level
    )



@app.route("/debug-categories")
def debug_categories():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM quiz_categories;")
        rows = cur.fetchall()
    return str(rows)


@app.route("/db-test")
def db_test():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        result = cur.fetchone()
        cur.close()
        conn.close()
        return f"DB 接続成功！<br>{result[0]}"
    except Exception as e:
        return f"DB 接続失敗 ❌<br>{e}"


# =============================
# 実行
# =============================
if __name__ == "__main__":
    app.run(debug=True, port=8000)
