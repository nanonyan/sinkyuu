
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

@app.route("/question")
def question():
    genre = request.args.get("genre")   # 例: レジ
    level = request.args.get("level")   # Easy / Normal / Hard

    if not genre or not level:
        return "パラメータが不足しています"

    level_map = {
        "Easy": 1,
        "Normal": 2,
        "Hard": 3
    }
    difficulty = level_map.get(level)

    if difficulty is None:
        return "不正なレベルです"

    conn = get_db_connection()

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # ① 問題を1問取得
        cur.execute("""
            SELECT
                q.id,
                q.question_text
            FROM quiz_questions q
            JOIN quiz_categories cat ON q.category_id = cat.id
            WHERE cat.name = %s
              AND q.difficulty = %s
            ORDER BY q.id
            LIMIT 1
        """, (genre, difficulty))

        question = cur.fetchone()

        if not question:
            return render_template(
                "question.html",
                question={"question_text": "問題が見つかりません"},
                choices=[]
            )

        # ② 選択肢（正解フラグ含む）を取得
        cur.execute("""
            SELECT
                id,
                choice_text,
                is_correct
            FROM quiz_choices
            WHERE question_id = %s
            ORDER BY id
        """, (question["id"],))

        rows = cur.fetchall()

    # ③ correct_choice_id を決定
    correct_choice_id = None
    choices = []

    for row in rows:
        choices.append({
            "id": row["id"],
            "choice_text": row["choice_text"]
        })
        if row["is_correct"]:
            correct_choice_id = row["id"]

    return render_template(
        "question.html",
        question={
            "id": question["id"],
            "question_text": question["question_text"],
            "correct_choice_id": correct_choice_id
        },
        choices=choices
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
