import os, json, uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

from flask import Flask, request, jsonify, render_template, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import text

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE-ME-before-production-" + str(uuid.uuid4()))
db_url = os.environ.get("DATABASE_URL", "sqlite:///exam_server.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="exam-server-token-v1")

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.isoformat() if dt else None

def parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("starts_at must include a timezone, for example +03:00 or Z")
        return dt.astimezone(timezone.utc)
    except Exception:
        raise ValueError("صيغة وقت البدء غير صحيحة. استخدم ISO 8601 مع المنطقة الزمنية.")

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc, nullable=False)

class Exam(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    teacher_id = db.Column(db.Integer, db.ForeignKey("teacher.id"), nullable=False, index=True)
    title = db.Column(db.String(240), nullable=False)
    subject = db.Column(db.String(160), default="")
    grade = db.Column(db.String(160), default="")
    payload = db.Column(db.JSON, nullable=False, default=dict)
    duration_minutes = db.Column(db.Integer, nullable=True)
    starts_at = db.Column(db.DateTime(timezone=True), nullable=True)
    public_token = db.Column(db.String(48), unique=True, nullable=False, index=True)
    published = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.String(36), db.ForeignKey("exam.id"), nullable=False, index=True)
    student_name = db.Column(db.String(160), nullable=False)
    student_ref = db.Column(db.String(120), default="")
    answers = db.Column(db.JSON, nullable=False, default=dict)
    submitted_at = db.Column(db.DateTime(timezone=True), default=now_utc, nullable=False)

class Attempt(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = db.Column(db.String(36), db.ForeignKey("exam.id"), nullable=False, index=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=False)
    submitted = db.Column(db.Boolean, default=False, nullable=False)

def json_error(message, status=400):
    return jsonify({"error": message}), status

def bearer_teacher():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    try:
        data = serializer.loads(token, max_age=60 * 60 * 24 * 30)
        return db.session.get(Teacher, int(data["teacher_id"]))
    except (BadSignature, SignatureExpired, KeyError, ValueError, TypeError):
        return None

def require_teacher():
    teacher = bearer_teacher()
    if not teacher:
        return None, json_error("انتهت جلسة الدخول أو أن رمز المعلم غير صالح. سجّل الدخول مجدداً.", 401)
    return teacher, None

def exam_dict(exam):
    return {
        "id": exam.id, "title": exam.title, "subject": exam.subject,
        "grade": exam.grade, "duration_minutes": exam.duration_minutes,
        "starts_at": iso(exam.starts_at), "published": exam.published
    }

def student_url(exam):
    base = request.url_root.rstrip("/")
    return base + "/s/" + exam.public_token

@app.after_request
def cors(response):
    origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"] = origin or "*"
    response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response

@app.route("/<path:path>", methods=["OPTIONS"])
@app.route("/", methods=["OPTIONS"])
def options(path=""):
    return ("", 204)

@app.get("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ok", "service": "exam-server", "database": "connected"})
    except Exception:
        app.logger.exception("Health database check failed")
        return json_error("قاعدة البيانات غير متاحة حالياً.", 503)

@app.post("/api/v1/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if len(username) < 2 or len(username) > 60:
        return json_error("اسم المستخدم يجب أن يكون بين حرفين و60 حرفاً.")
    if len(password) < 8:
        return json_error("كلمة المرور يجب ألا تقل عن 8 أحرف.")
    if Teacher.query.filter_by(username=username).first():
        return json_error("اسم المستخدم مستخدم بالفعل. اختر اسماً آخر.", 409)
    teacher = Teacher(username=username, password_hash=generate_password_hash(password))
    db.session.add(teacher)
    db.session.commit()
    token = serializer.dumps({"teacher_id": teacher.id})
    return jsonify({"access_token": token, "token_type": "Bearer", "username": teacher.username}), 201

@app.post("/api/v1/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    teacher = Teacher.query.filter_by(username=username).first()
    if not teacher or not check_password_hash(teacher.password_hash, password):
        return json_error("اسم المستخدم أو كلمة المرور غير صحيحة.", 401)
    token = serializer.dumps({"teacher_id": teacher.id})
    return jsonify({"access_token": token, "token_type": "Bearer", "username": teacher.username})

@app.post("/api/v1/exams")
def create_exam():
    teacher, error = require_teacher()
    if error: return error
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:240]
    payload = data.get("payload")
    if not title: return json_error("اسم الاختبار مطلوب.")
    if not isinstance(payload, dict) or not isinstance(payload.get("questions"), list) or not payload["questions"]:
        return json_error("يجب أن يحتوي الاختبار على سؤال واحد على الأقل.")
    duration = data.get("duration_minutes")
    if duration is not None:
        try: duration = int(duration)
        except Exception: return json_error("مدة الاختبار غير صحيحة.")
        if duration < 1 or duration > 600: return json_error("مدة الاختبار يجب أن تكون بين 1 و600 دقيقة.")
    try:
        starts = parse_iso(data.get("starts_at"))
    except ValueError as e:
        return json_error(str(e))
    exam = Exam(
        teacher_id=teacher.id, title=title,
        subject=str(data.get("subject", ""))[:160],
        grade=str(data.get("grade", ""))[:160],
        payload=payload, duration_minutes=duration,
        starts_at=starts, public_token=uuid.uuid4().hex
    )
    db.session.add(exam)
    db.session.commit()
    return jsonify({"exam": exam_dict(exam), "student_url": student_url(exam)}), 201

@app.put("/api/v1/exams/<exam_id>")
def update_exam(exam_id):
    teacher, error = require_teacher()
    if error: return error
    exam = Exam.query.filter_by(id=exam_id, teacher_id=teacher.id).first()
    if not exam: return json_error("الاختبار غير موجود.", 404)
    data = request.get_json(silent=True) or {}
    if "title" in data: exam.title = str(data["title"]).strip()[:240] or exam.title
    if "subject" in data: exam.subject = str(data["subject"])[:160]
    if "grade" in data: exam.grade = str(data["grade"])[:160]
    if "payload" in data:
        p = data["payload"]
        if not isinstance(p, dict) or not isinstance(p.get("questions"), list) or not p["questions"]:
            return json_error("محتوى الاختبار غير صالح.")
        exam.payload = p
    if "duration_minutes" in data:
        d = data["duration_minutes"]
        if d is not None:
            try: d = int(d)
            except Exception: return json_error("مدة الاختبار غير صحيحة.")
            if d < 1 or d > 600: return json_error("مدة الاختبار يجب أن تكون بين 1 و600 دقيقة.")
        exam.duration_minutes = d
    if "starts_at" in data:
        try: exam.starts_at = parse_iso(data.get("starts_at"))
        except ValueError as e: return json_error(str(e))
    db.session.commit()
    return jsonify({"exam": exam_dict(exam), "student_url": student_url(exam)})

@app.post("/api/v1/exams/<exam_id>/publish")
def publish_exam(exam_id):
    teacher, error = require_teacher()
    if error: return error
    exam = Exam.query.filter_by(id=exam_id, teacher_id=teacher.id).first()
    if not exam: return json_error("الاختبار غير موجود.", 404)
    exam.published = True
    db.session.commit()
    return jsonify({"exam": exam_dict(exam), "student_url": student_url(exam)})

@app.get("/api/v1/exams/<exam_id>/submissions")
def list_submissions(exam_id):
    teacher, error = require_teacher()
    if error: return error
    exam = Exam.query.filter_by(id=exam_id, teacher_id=teacher.id).first()
    if not exam: return json_error("الاختبار غير موجود.", 404)
    rows = Submission.query.filter_by(exam_id=exam.id).order_by(Submission.submitted_at.asc()).all()
    return jsonify({"submissions": [{
        "id": row.id, "student_name": row.student_name,
        "student_ref": row.student_ref, "answers": row.answers,
        "submitted_at": iso(row.submitted_at)
    } for row in rows]})

def find_public_exam(token):
    exam = Exam.query.filter_by(public_token=token, published=True).first()
    if not exam: abort(404)
    return exam

@app.get("/s/<token>")
def student_page(token):
    exam = find_public_exam(token)
    return render_template("student.html", token=token, exam=exam)

@app.get("/api/v1/student/<token>")
def student_exam(token):
    exam = find_public_exam(token)
    if exam.starts_at and now_utc() < exam.starts_at:
        return json_error("لم يبدأ الاختبار بعد.", 403)
    return jsonify({"title": exam.title, "subject": exam.subject, "grade": exam.grade,
                    "duration_minutes": exam.duration_minutes,
                    "questions": exam.payload.get("questions", [])})

@app.post("/api/v1/student/<token>/start")
def student_start(token):
    exam = find_public_exam(token)
    if exam.starts_at and now_utc() < exam.starts_at:
        return json_error("لم يبدأ الاختبار بعد.", 403)
    attempt = Attempt(exam_id=exam.id, started_at=now_utc())
    db.session.add(attempt)
    db.session.commit()
    signed = serializer.dumps({"attempt_id": attempt.id, "exam_id": exam.id})
    return jsonify({"attempt_token": signed, "started_at": iso(attempt.started_at),
                    "duration_minutes": exam.duration_minutes})

@app.post("/api/v1/student/<token>/submit")
def student_submit(token):
    exam = find_public_exam(token)
    data = request.get_json(silent=True) or {}
    name = str(data.get("student_name", "")).strip()[:160]
    student_ref = str(data.get("student_ref", "")).strip()[:120]
    answers = data.get("answers")
    signed = str(data.get("attempt_token", ""))
    if not name: return json_error("اكتب اسم الطالب.")
    if not isinstance(answers, dict): return json_error("الإجابات غير صالحة.")
    try:
        info = serializer.loads(signed, max_age=60 * 60 * 12)
        attempt = db.session.get(Attempt, info["attempt_id"])
        if not attempt or info.get("exam_id") != exam.id or attempt.exam_id != exam.id:
            return json_error("جلسة الاختبار غير صالحة. افتح الرابط مجدداً.", 403)
    except (BadSignature, SignatureExpired, KeyError, TypeError):
        return json_error("انتهت جلسة الاختبار. افتح الرابط مجدداً.", 403)
    if attempt.submitted: return json_error("تم إرسال إجابات هذه المحاولة مسبقاً.", 409)
    if exam.duration_minutes:
        deadline = attempt.started_at + timedelta(minutes=exam.duration_minutes)
        if now_utc() > deadline: return json_error("انتهى الوقت المخصص للاختبار.", 403)
    attempt.submitted = True
    submission = Submission(exam_id=exam.id, student_name=name, student_ref=student_ref, answers=answers)
    db.session.add(submission)
    db.session.commit()
    return jsonify({"ok": True, "message": "تم استلام إجاباتك بنجاح."}), 201

@app.errorhandler(404)
def not_found(_):
    return json_error("المسار أو الاختبار غير موجود.", 404)

@app.errorhandler(500)
def server_error(_):
    db.session.rollback()
    app.logger.exception("Unhandled server error")
    return json_error("حدث خطأ داخلي في الخادم.", 500)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
