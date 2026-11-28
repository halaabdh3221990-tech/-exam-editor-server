 import os
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import UniqueConstraint


app = Flask(__name__)

# -------------------------------------------------
# Configuration
# -------------------------------------------------

database_url = os.environ.get("DATABASE_URL", "sqlite:///exam_editor.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "change-this-secret-before-production"
)

db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def now_utc():
    return datetime.now(timezone.utc)


def iso(value):
    if not value:
        return None
    return value.isoformat()


def error(message, status=400):
    return jsonify({"error": message}), status


def get_json():
    return request.get_json(silent=True) or {}


# -------------------------------------------------
# Database models
# -------------------------------------------------

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)


class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("teacher.id"), nullable=False)

    title = db.Column(db.String(255), nullable=False, default="اختبار جديد")
    duration_minutes = db.Column(db.Integer, nullable=False, default=30)

    # Stores the editor's complete exam data, including formatting,
    # images, shapes, tables and questions.
    payload = db.Column(db.JSON, nullable=False, default=dict)

    public_token = db.Column(db.String(100), unique=True, nullable=True)
    published = db.Column(db.Boolean, default=False)
    grading_mode = db.Column(db.String(30), default="manual")

    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)


class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    attempt_token = db.Column(db.String(100), unique=True, nullable=False)

    student_name = db.Column(db.String(255), nullable=False)
    student_ref = db.Column(db.String(120), nullable=True)

    started_at = db.Column(db.DateTime(timezone=True), default=now_utc)
    submitted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    submitted = db.Column(db.Boolean, default=False)


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exam.id"), nullable=False)
    attempt_id = db.Column(db.Integer, db.ForeignKey("attempt.id"), nullable=False)

    student_name = db.Column(db.String(255), nullable=False)
    student_ref = db.Column(db.String(120), nullable=True)
    answers = db.Column(db.JSON, nullable=False, default=dict)

    submitted_at = db.Column(db.DateTime(timezone=True), default=now_utc)


class SubmissionGrade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(
        db.Integer, db.ForeignKey("submission.id"), unique=True, nullable=False
    )
    score = db.Column(db.Float, nullable=True)
    total_marks = db.Column(db.Float, nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    grading_type = db.Column(db.String(30), default="manual")
    graded_at = db.Column(db.DateTime(timezone=True), default=now_utc)


# -------------------------------------------------
# Authentication
# -------------------------------------------------

def create_auth_token(teacher):
    return serializer.dumps(
        {"teacher_id": teacher.id},
        salt="teacher-auth"
    )


def current_teacher():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None

    token = header.split(" ", 1)[1].strip()

    try:
        data = serializer.loads(
            token,
            salt="teacher-auth",
            max_age=60 * 60 * 24 * 30
        )
    except (BadSignature, SignatureExpired):
        return None

    return db.session.get(Teacher, data.get("teacher_id"))


def require_teacher(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        teacher = current_teacher()

        if not teacher:
            return error("تسجيل الدخول مطلوب أو انتهت صلاحية الجلسة", 401)

        request.teacher = teacher
        return function(*args, **kwargs)

    return wrapper


# -------------------------------------------------
# Exam helpers
# -------------------------------------------------

def exam_dict(exam):
    return {
        "id": exam.id,
        "title": exam.title,
        "duration_minutes": exam.duration_minutes,
        "payload": exam.payload,
        "published": exam.published,
        "public_token": exam.public_token,
        "grading_mode": exam.grading_mode,
        "created_at": iso(exam.created_at),
    }


def remove_answer_keys(value):
    """Remove answer keys before sending questions to students."""
    if isinstance(value, list):
        return [remove_answer_keys(item) for item in value]

    if isinstance(value, dict):
        hidden = {
            "correct_answer",
            "correct_answers",
            "answer_key",
            "solution",
            "model_answer",
        }
        return {
            key: remove_answer_keys(item)
            for key, item in value.items()
            if key not in hidden
        }

    return value


def get_questions(exam):
    payload = exam.payload or {}

    if isinstance(payload, list):
        return payload

    return payload.get("questions", [])


def auto_grade(exam, answers):
    """
    Optional basic electronic grading.
    Questions need: id, correct_answer and marks.
    Answers should be keyed by question id.
    """
    questions = get_questions(exam)
    score = 0.0
    total = 0.0
    graded_any = False

    for index, question in enumerate(questions):
        if not isinstance(question, dict):
            continue

        if "correct_answer" not in question:
            continue

        question_id = str(question.get("id", index))
        correct = question.get("correct_answer")
        student_answer = answers.get(question_id)

        marks = float(question.get("marks", 1) or 1)
        total += marks
        graded_any = True

        if str(student_answer).strip().casefold() == str(correct).strip().casefold():
            score += marks

    if not graded_any:
        return None, None

    return score, total


# -------------------------------------------------
# Health
# -------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "exam-editor-server",
        "status": "ok",
        "time": iso(now_utc())
    })


# -------------------------------------------------
# Teacher registration and login
# -------------------------------------------------

@app.route("/api/v1/auth/register", methods=["POST"])
def register():
    data = get_json()

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if len(username) < 3 or len(password) < 6:
        return error("اسم المستخدم 3 أحرف على الأقل وكلمة المرور 6 أحرف على الأقل")

    if Teacher.query.filter_by(username=username).first():
        return error("اسم المستخدم مستخدم بالفعل", 409)

    from werkzeug.security import generate_password_hash

    teacher = Teacher(
        username=username,
        password_hash=generate_password_hash(password)
    )

    db.session.add(teacher)
    db.session.commit()

    return jsonify({
        "message": "تم إنشاء حساب المعلم",
        "token": create_auth_token(teacher),
        "teacher": {"id": teacher.id, "username": teacher.username}
    }), 201


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = get_json()

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    teacher = Teacher.query.filter_by(username=username).first()

    if not teacher:
        return error("اسم المستخدم أو كلمة المرور غير صحيحة", 401)

    from werkzeug.security import check_password_hash

    if not check_password_hash(teacher.password_hash, password):
        return error("اسم المستخدم أو كلمة المرور غير صحيحة", 401)

    return jsonify({
        "message": "تم تسجيل الدخول",
        "token": create_auth_token(teacher),
        "teacher": {"id": teacher.id, "username": teacher.username}
    })


# -------------------------------------------------
# Teacher exam management
# -------------------------------------------------

@app.route("/api/v1/exams", methods=["POST"])
@require_teacher
def create_exam():
    data = get_json()

    payload = data.get("payload")

    if payload is None:
        payload = {"questions": data.get("questions", [])}

    if not isinstance(payload, (dict, list)):
        return error("بيانات الاختبار غير صحيحة")

    try:
        duration = int(data.get("duration_minutes", 30))
    except (TypeError, ValueError):
        return error("مدة الاختبار غير صحيحة")

    if duration < 1:
        return error("مدة الاختبار يجب أن تكون دقيقة واحدة على الأقل")

    exam = Exam(
        teacher_id=request.teacher.id,
        title=str(data.get("title", "اختبار جديد")),
        duration_minutes=duration,
        payload=payload,
        grading_mode=data.get("grading_mode", "manual")
    )

    db.session.add(exam)
    db.session.commit()

    return jsonify({
        "message": "تم إنشاء الاختبار",
        "exam": exam_dict(exam)
    }), 201


@app.route("/api/v1/exams", methods=["GET"])
@require_teacher
def list_exams():
    exams = Exam.query.filter_by(
        teacher_id=request.teacher.id
    ).order_by(Exam.id.desc()).all()

    return jsonify({"exams": [exam_dict(exam) for exam in exams]})


@app.route("/api/v1/exams/<int:exam_id>", methods=["GET"])
@require_teacher
def get_exam(exam_id):
    exam = Exam.query.filter_by(
        id=exam_id,
        teacher_id=request.teacher.id
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    return jsonify({"exam": exam_dict(exam)})


@app.route("/api/v1/exams/<int:exam_id>", methods=["PUT"])
@require_teacher
def update_exam(exam_id):
    exam = Exam.query.filter_by(
        id=exam_id,
        teacher_id=request.teacher.id
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    data = get_json()

    if "title" in data:
        exam.title = str(data["title"])

    if "duration_minutes" in data:
        try:
            duration = int(data["duration_minutes"])
        except (TypeError, ValueError):
            return error("مدة الاختبار غير صحيحة")

        if duration < 1:
            return error("مدة الاختبار غير صحيحة")

        exam.duration_minutes = duration

    if "payload" in data:
        if not isinstance(data["payload"], (dict, list)):
            return error("بيانات الاختبار غير صحيحة")
        exam.payload = data["payload"]

    if "questions" in data and "payload" not in data:
        exam.payload = {"questions": data["questions"]}

    if data.get("grading_mode") in ("manual", "electronic"):
        exam.grading_mode = data["grading_mode"]

    db.session.commit()

    return jsonify({
        "message": "تم تحديث الاختبار",
        "exam": exam_dict(exam)
    })


@app.route("/api/v1/exams/<int:exam_id>/publish", methods=["POST"])
@require_teacher
def publish_exam(exam_id):
    exam = Exam.query.filter_by(
        id=exam_id,
        teacher_id=request.teacher.id
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    if not exam.public_token:
        exam.public_token = secrets.token_urlsafe(24)

    exam.published = True
    db.session.commit()

    return jsonify({
        "message": "تم نشر الاختبار",
        "public_token": exam.public_token,
        "student_url": request.host_url.rstrip("/") + "/s/" + exam.public_token
    })


# -------------------------------------------------
# Student page and exam details
# -------------------------------------------------

@app.route("/s/<token>", methods=["GET"])
def student_page(token):
    exam = Exam.query.filter_by(
        public_token=token,
        published=True
    ).first()

    if not exam:
        return "الاختبار غير موجود أو لم يتم نشره", 404

    return render_template("student.html", token=token)


@app.route("/api/v1/student/<token>", methods=["GET"])
def student_exam(token):
    exam = Exam.query.filter_by(
        public_token=token,
        published=True
    ).first()

    if not exam:
        return error("الاختبار غير موجود أو لم يتم نشره", 404)

    questions = remove_answer_keys(get_questions(exam))

    return jsonify({
        "title": exam.title,
        "duration_minutes": exam.duration_minutes,
        "questions": questions
    })


# -------------------------------------------------
# Student starts an attempt
# -------------------------------------------------

@app.route("/api/v1/student/<token>/start", methods=["POST"])
def student_start(token):
    exam = Exam.query.filter_by(
        public_token=token,
        published=True
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    data = get_json()

    student_name = str(data.get("student_name", "")).strip()
    student_ref = str(data.get("student_ref", "")).strip()

    if not student_name:
        return error("يرجى كتابة اسم الطالب")

    attempt = Attempt(
        exam_id=exam.id,
        attempt_token=secrets.token_urlsafe(32),
        student_name=student_name,
        student_ref=student_ref or None,
        started_at=now_utc()
    )

    db.session.add(attempt)
    db.session.commit()

    return jsonify({
        "message": "بدأ الاختبار",
        "attempt_token": attempt.attempt_token,
        "started_at": iso(attempt.started_at),
        "duration_minutes": exam.duration_minutes,
        "student_name": student_name,
        "student_ref": student_ref
    })


# -------------------------------------------------
# Student submits answers
# -------------------------------------------------

@app.route("/api/v1/student/<token>/submit", methods=["POST"])
def student_submit(token):
    exam = Exam.query.filter_by(
        public_token=token,
        published=True
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    data = get_json()

    attempt_token = str(data.get("attempt_token", "")).strip()

    if not attempt_token:
        return error("رمز المحاولة مفقود")

    attempt = Attempt.query.filter_by(
        attempt_token=attempt_token,
        exam_id=exam.id
    ).first()

    if not attempt:
        return error("محاولة الاختبار غير صحيحة", 404)

    if attempt.submitted:
        return error("تم إرسال إجابات هذه المحاولة مسبقاً", 409)

    answers = data.get("answers", {})

    if not isinstance(answers, (dict, list)):
        return error("صيغة الإجابات غير صحيحة")

    # Check the allowed test duration.
    started = attempt.started_at

    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)

    elapsed = now_utc() - started
    allowed = timedelta(minutes=exam.duration_minutes)

    if elapsed > allowed + timedelta(minutes=2):
        return error("انتهى وقت الاختبار")

    submission = Submission(
        exam_id=exam.id,
        attempt_id=attempt.id,
        student_name=attempt.student_name,
        student_ref=attempt.student_ref,
        answers=answers,
        submitted_at=now_utc()
    )

    db.session.add(submission)

    attempt.submitted = True
    attempt.submitted_at = now_utc()

    # Optional basic electronic grading.
    if exam.grading_mode == "electronic" and isinstance(answers, dict):
        score, total = auto_grade(exam, answers)

        if score is not None:
            grade = SubmissionGrade(
                submission_id=submission.id,
                score=score,
                total_marks=total,
                grading_type="electronic"
            )
            db.session.flush()
            db.session.add(grade)

    db.session.commit()

    return jsonify({
        "message": "تم استلام إجابات الطالب بنجاح",
        "submission_id": submission.id
    }), 201


# -------------------------------------------------
# Teacher views student answers
# -------------------------------------------------

@app.route("/api/v1/exams/<int:exam_id>/submissions", methods=["GET"])
@require_teacher
def list_submissions(exam_id):
    exam = Exam.query.filter_by(
        id=exam_id,
        teacher_id=request.teacher.id
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    submissions = Submission.query.filter_by(
        exam_id=exam.id
    ).order_by(Submission.submitted_at.desc()).all()

    result = []

    for submission in submissions:
        grade = SubmissionGrade.query.filter_by(
            submission_id=submission.id
        ).first()

        result.append({
            "id": submission.id,
            "student_name": submission.student_name,
            "student_ref": submission.student_ref,
            "answers": submission.answers,
            "submitted_at": iso(submission.submitted_at),
            "score": grade.score if grade else None,
            "total_marks": grade.total_marks if grade else None,
            "feedback": grade.feedback if grade else None,
            "grading_type": grade.grading_type if grade else None
        })

    return jsonify({
        "exam_id": exam.id,
        "exam_title": exam.title,
        "submissions": result
    })


# -------------------------------------------------
# Teacher manually grades a submission
# -------------------------------------------------

@app.route(
    "/api/v1/exams/<int:exam_id>/submissions/<int:submission_id>/grade",
    methods=["PUT"]
)
@require_teacher
def grade_submission(exam_id, submission_id):
    exam = Exam.query.filter_by(
        id=exam_id,
        teacher_id=request.teacher.id
    ).first()

    if not exam:
        return error("الاختبار غير موجود", 404)

    submission = Submission.query.filter_by(
        id=submission_id,
        exam_id=exam.id
    ).first()

    if not submission:
        return error("إجابة الطالب غير موجودة", 404)

    data = get_json()

    try:
        score = float(data.get("score"))
        total_marks = float(data.get("total_marks"))
    except (TypeError, ValueError):
        return error("يرجى إدخال الدرجة والدرجة النهائية بشكل صحيح")

    if total_marks <= 0 or score < 0 or score > total_marks:
        return error("الدرجات المدخلة غير صحيحة")

    grade = SubmissionGrade.query.filter_by(
        submission_id=submission.id
    ).first()

    if not grade:
        grade = SubmissionGrade(submission_id=submission.id)
        db.session.add(grade)

    grade.score = score
    grade.total_marks = total_marks
    grade.feedback = str(data.get("feedback", ""))
    grade.grading_type = "manual"
    grade.graded_at = now_utc()

    db.session.commit()

    return jsonify({
        "message": "تم حفظ تصحيح الطالب ودرجته",
        "submission_id": submission.id,
        "score": grade.score,
        "total_marks": grade.total_marks,
        "feedback": grade.feedback,
        "grading_type": grade.grading_type
    })


# -------------------------------------------------
# Database initialization
# -------------------------------------------------

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
