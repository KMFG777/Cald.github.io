from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import text
import os
from datetime import datetime, timedelta
import feedparser
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from flask_talisman import Talisman
import feedparser
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_FILES = {'zip', 'rar', '7z', 'pdf', 'txt'}

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
# talisman = Talisman(app, content_security_policy=None) # CSP disabled to avoid breaking inline scripts/styles for now

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100))
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    user = db.relationship('User', backref='profile', uselist=False)
    avatar_url = db.Column(db.String(500))
    display_name = db.Column(db.String(100))

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    download_link = db.Column(db.String(500))
    file_name = db.Column(db.String(300)) # Store original filename
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    image_url = db.Column(db.String(500))
    url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_name = db.Column(db.String(100), default="Anonymous") # Added for non-logged in users
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Allow null
    sender = db.relationship('User', backref='messages')
    content = db.Column(db.Text)
    reply = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='password_resets')
    code = db.Column(db.String(6))
    expires_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean, default=False)
class PublicChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    addressee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='accepted')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin Setup
def create_admin():
    admin = User.query.filter_by(username='CaldAllEmail').first()
    hashed_pw = generate_password_hash('88KKhh88', method='pbkdf2:sha256')
    
    if not admin:
        admin = User(
            name='كالد | Cald',
            username='CaldAllEmail',
            email='cald.allemail@gmail.com',
            password_hash=hashed_pw,
            is_admin=True
        )
        db.session.add(admin)
        print("Admin user created.")
    else:
        # Update password if admin exists
        admin.password_hash = hashed_pw
        admin.is_admin = True # Ensure admin rights
        print("Admin password updated.")
        
    db.session.commit()

# Context Processor for common data
@app.context_processor
def inject_now():
    prof = None
    if current_user.is_authenticated:
        prof = Profile.query.filter_by(user_id=current_user.id).first()
    return {'now': datetime.utcnow(), 'current_profile': prof}
def init_db():
    db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    try:
        cols = [r[1] for r in db.session.execute(text("PRAGMA table_info(message)")).fetchall()]
        if 'sender_name' not in cols:
            db.session.execute(text("ALTER TABLE message ADD COLUMN sender_name TEXT DEFAULT 'Anonymous'"))
            db.session.commit()
    except Exception:
        pass
    try:
        cols = [r[1] for r in db.session.execute(text("PRAGMA table_info(project)")).fetchall()]
        if 'file_name' not in cols:
            db.session.execute(text("ALTER TABLE project ADD COLUMN file_name TEXT"))
            db.session.commit()
    except Exception:
        pass
    create_admin()
with app.app_context():
    init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/projects')
def projects():
    all_projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('projects.html', projects=all_projects)

@app.route('/links')
def links():
    all_links = Link.query.order_by(Link.created_at.desc()).all()
    return render_template('links.html', links=all_links)

# AI Videos route removed as per request

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_id = request.form.get('login_id') # Can be username, email or name
        password = request.form.get('password')
        
        user = User.query.filter((User.username==login_id) | (User.email==login_id) | (User.name==login_id)).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('تم تسجيل الدخول بنجاح', 'success')
            return redirect(url_for('settings'))
        else:
            flash('بيانات الدخول غير صحيحة', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('كلمة المرور غير متطابقة', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('اسم المستخدم مستخدم بالفعل', 'error')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, username=username, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('تم إنشاء الحساب وتسجيل الدخول', 'success')
        return redirect(url_for('settings'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    messages_new = Message.query.filter(Message.reply.is_(None)).order_by(Message.created_at.desc()).all()
    messages_replied = Message.query.filter(Message.reply.isnot(None)).order_by(Message.created_at.desc()).all()
    return render_template('dashboard.html', messages_new=messages_new, messages_replied=messages_replied)

@app.route('/dashboard/reply/<int:msg_id>', methods=['POST'])
@login_required
def reply_message(msg_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    msg = Message.query.get_or_404(msg_id)
    reply_content = request.form.get('reply')
    msg.reply = reply_content
    msg.is_read = True
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/dashboard/delete_message/<int:msg_id>', methods=['POST'])
@login_required
def delete_message(msg_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    msg = Message.query.get_or_404(msg_id)
    db.session.delete(msg)
    db.session.commit()
    flash('تم حذف الرسالة', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard/add_project', methods=['POST'])
@login_required
def add_project():
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    title = request.form.get('title')
    description = request.form.get('description')
    image_url = request.form.get('image_url')
    allow_download = request.form.get('allow_download') == 'on'
    project_link = request.form.get('project_link')

    # handle optional image upload
    if 'image_file' in request.files:
        img = request.files.get('image_file')
        if img and img.filename:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            img_name = secure_filename(img.filename)
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], img_name)
            img.save(img_path)
            path_fixed = img_path.replace('\\', '/')
            image_url = f"/{path_fixed}"

    # handle optional project file upload
    download_link = None
    original_name = None
    if allow_download:
        if project_link:
            download_link = project_link
        elif 'project_file' in request.files:
            pf = request.files.get('project_file')
            if pf and pf.filename:
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                pf_name = secure_filename(pf.filename)
                if not pf_name:
                    pf_name = f"file_{int(datetime.utcnow().timestamp())}"
                pf_path = os.path.join(app.config['UPLOAD_FOLDER'], pf_name)
                pf.save(pf_path)
                download_link = f"/{pf_path.replace('\\', '/')}"
                original_name = pf.filename

    new_project = Project(title=title, description=description, image_url=image_url, download_link=download_link, file_name=original_name)
    db.session.add(new_project)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/dashboard/add_link', methods=['POST'])
@login_required
def add_link():
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    title = request.form.get('title')
    image_url = request.form.get('image_url')
    url = request.form.get('url')
    
    if 'image_file' in request.files:
        img = request.files.get('image_file')
        if img and img.filename:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            img_name = secure_filename(img.filename)
            img_path = os.path.join(app.config['UPLOAD_FOLDER'], img_name)
            img.save(img_path)
            path_fixed = img_path.replace('\\', '/')
            image_url = f"/{path_fixed}"

    new_link = Link(title=title, image_url=image_url, url=url)
    db.session.add(new_link)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_project/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    p = Project.query.get_or_404(project_id)
    db.session.delete(p)
    db.session.commit()
    flash('تم حذف المشروع', 'success')
    return redirect(request.referrer or url_for('projects'))

@app.route('/delete_link/<int:link_id>', methods=['POST'])
@login_required
def delete_link(link_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    l = Link.query.get_or_404(link_id)
    db.session.delete(l)
    db.session.commit()
    flash('تم حذف الرابط', 'success')
    return redirect(request.referrer or url_for('links'))
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            return jsonify({'response': 'الرسالة فارغة!'})
            
        sender_id = current_user.id if current_user.is_authenticated else None
        sender_name = current_user.name if current_user.is_authenticated else "زائر"
        if sender_id is None:
            admin = User.query.filter_by(is_admin=True).first()
            sender_id = admin.id if admin else None
        
        new_msg = Message(sender_id=sender_id, sender_name=sender_name, content=content)
        db.session.add(new_msg)
        db.session.commit()
        
        return jsonify({'response': 'تم إرسال رسالتك إلى كالد بنجاح. سيتم الرد عليك قريباً!'})
        
    return render_template('chat.html')
@app.route('/room', methods=['GET'])
@login_required
def room():
    friends = Friendship.query.filter((Friendship.requester_id==current_user.id) | (Friendship.addressee_id==current_user.id), Friendship.status=='accepted').all()
    friend_names = []
    for f in friends:
        fid = f.addressee_id if f.requester_id==current_user.id else f.requester_id
        u = User.query.get(fid)
        if u:
            friend_names.append(u.name)
    return render_template('room.html', friends=friends, friend_names=friend_names)
@app.route('/room/upload', methods=['POST'])
@login_required
def room_upload():
    files = request.files.getlist('files')
    saved = []
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    for f in files:
        if f and f.filename:
            name = secure_filename(f.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], name)
            f.save(path)
            saved.append(f"/{path.replace('\\', '/')}")
    return jsonify({'files': saved})
@app.route('/api/tool/code', methods=['POST'])
@login_required
def api_tool_code():
    prompt = request.form.get('prompt', '')
    lang = 'python' if 'python' in prompt.lower() else 'javascript' if 'js' in prompt.lower() else 'text'
    if lang == 'python':
        code = f"def main():\n    print('{prompt[:50]}')\n\nif __name__ == '__main__':\n    main()"
    elif lang == 'javascript':
        code = f"function main() {{ console.log('{prompt[:50]}'); }}\nmain();"
    else:
        code = f"{prompt}"
    return jsonify({'language': lang, 'code': code})
@app.route('/api/tool/info', methods=['POST'])
@login_required
def api_tool_info():
    query = request.form.get('query', '')
    try:
        r = requests.get('https://api.duckduckgo.com/', params={'q': query, 'format': 'json'}, timeout=6)
        j = r.json()
        abstract = j.get('AbstractText') or ''
        topics = []
        for t in j.get('RelatedTopics', [])[:5]:
            if isinstance(t, dict):
                topics.append({'text': t.get('Text'), 'url': t.get('FirstURL')})
        return jsonify({'abstract': abstract, 'topics': topics})
    except Exception:
        return jsonify({'abstract': '', 'topics': []})
@app.route('/api/tool/image', methods=['POST'])
@login_required
def api_tool_image():
    prompt = request.form.get('prompt', '')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    name = f"generated_{int(datetime.utcnow().timestamp())}.svg"
    path = os.path.join(app.config['UPLOAD_FOLDER'], name)
    svg = f"<svg xmlns='http://www.w3.org/2000/svg' width='800' height='450'><rect width='100%' height='100%' fill='#111'/><text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#ff3d3d' font-size='24' font-family='Segoe UI'>{prompt}</text></svg>"
    with open(path, 'w', encoding='utf-8') as fp:
        fp.write(svg)
    url = f"/{path.replace('\\', '/')}"
    return jsonify({'image_url': url})
@app.route('/api/chat/public/messages')
def api_public_messages():
    msgs = PublicChatMessage.query.order_by(PublicChatMessage.created_at.desc()).limit(50).all()
    data = [{'id': m.id, 'user': User.query.get(m.user_id).name if m.user_id else 'زائر', 'content': m.content, 'at': m.created_at.strftime('%H:%M')} for m in msgs]
    return jsonify(data)
@app.route('/api/chat/public/send', methods=['POST'])
@login_required
def api_public_send():
    content = request.form.get('content')
    if not content:
        return jsonify({'ok': False})
    m = PublicChatMessage(user_id=current_user.id, content=content)
    db.session.add(m)
    db.session.commit()
    return jsonify({'ok': True})
@app.route('/friends/add', methods=['POST'])
@login_required
def friends_add():
    uname = request.form.get('username')
    u = User.query.filter_by(username=uname).first()
    if not u or u.id == current_user.id:
        flash('لا يمكن إضافة هذا المستخدم', 'error')
        return redirect(url_for('room'))
    exists = Friendship.query.filter(((Friendship.requester_id==current_user.id) & (Friendship.addressee_id==u.id)) | ((Friendship.requester_id==u.id) & (Friendship.addressee_id==current_user.id))).first()
    if not exists:
        f = Friendship(requester_id=current_user.id, addressee_id=u.id, status='accepted')
        db.session.add(f)
        db.session.commit()
        flash('تمت إضافة الصديق', 'success')
    else:
        flash('الصديق موجود مسبقاً', 'error')
    return redirect(url_for('room'))

@app.route('/my_replies')
@login_required
def my_replies():
    replies = Message.query.filter(Message.sender_id==current_user.id, Message.reply.isnot(None)).order_by(Message.created_at.desc()).all()
    data = [{'id': m.id, 'content': m.content, 'reply': m.reply, 'at': m.created_at.strftime('%Y-%m-%d %H:%M')} for m in replies]
    return jsonify(data)

@app.route('/delete_my_message/<int:msg_id>', methods=['POST'])
@login_required
def delete_my_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    if msg.sender_id != current_user.id:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 403
    db.session.delete(msg)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/get_videos')
def get_videos():
    return jsonify([]) # Disabled

# Settings
@app.route('/settings', methods=['GET'])
@login_required
def settings():
    # create profile if missing
    prof = Profile.query.filter_by(user_id=current_user.id).first()
    if not prof:
        prof = Profile(user_id=current_user.id, display_name=current_user.name)
        db.session.add(prof)
        db.session.commit()
    return render_template('settings.html', profile=prof)

@app.route('/settings/profile', methods=['POST'])
@login_required
def settings_profile():
    display_name = request.form.get('display_name')
    avatar_url = request.form.get('avatar_url')
    prof = Profile.query.filter_by(user_id=current_user.id).first()
    if not prof:
        prof = Profile(user_id=current_user.id)
        db.session.add(prof)
    prof.display_name = display_name or current_user.name
    prof.avatar_url = avatar_url
    # also update user name (not username)
    current_user.name = prof.display_name
    db.session.commit()
    flash('تم تحديث معلومات الحساب', 'success')
    return redirect(url_for('settings'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/settings/avatar', methods=['POST'])
@login_required
def settings_avatar():
    if 'avatar' not in request.files:
        flash('لم يتم اختيار صورة', 'error')
        return redirect(url_for('settings'))
    file = request.files['avatar']
    if file.filename == '':
        flash('اسم ملف الصورة فارغ', 'error')
        return redirect(url_for('settings'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        url = f"/{save_path.replace('\\', '/')}"
        prof = Profile.query.filter_by(user_id=current_user.id).first()
        if not prof:
            prof = Profile(user_id=current_user.id)
            db.session.add(prof)
        prof.avatar_url = url
        db.session.commit()
        flash('تم تحديث صورة الحساب', 'success')
        return redirect(url_for('settings'))
    else:
        flash('صيغة الصورة غير مدعومة', 'error')
        return redirect(url_for('settings'))

@app.route('/settings/request_code', methods=['POST'])
@login_required
def settings_request_code():
    # generate code and store
    code = f"{os.urandom(3).hex()}"[:6].upper()
    expires = datetime.utcnow() + timedelta(minutes=10)
    # invalidate previous codes
    PasswordReset.query.filter_by(user_id=current_user.id, used=False).delete()
    req = PasswordReset(user_id=current_user.id, code=code, expires_at=expires, used=False)
    db.session.add(req)
    db.session.commit()
    # simulate email sending by printing to console
    print(f"Verification code for {current_user.email}: {code} (valid 10 mins)")
    flash('تم إرسال رمز التحقق إلى بريدك (بيئة تطوير: الرمز ظهر في الطرفية)')
    return redirect(url_for('settings'))

@app.route('/settings/change_password', methods=['POST'])
@login_required
def settings_change_password():
    old_pw = request.form.get('old_password')
    new_pw = request.form.get('new_password')
    confirm_new = request.form.get('confirm_new_password')
    if not check_password_hash(current_user.password_hash, old_pw):
        flash('كلمة المرور القديمة غير صحيحة')
        return redirect(url_for('settings'))
    if new_pw != confirm_new:
        flash('كلمة المرور الجديدة غير متطابقة')
        return redirect(url_for('settings'))
    # update password
    current_user.password_hash = generate_password_hash(new_pw, method='pbkdf2:sha256')
    db.session.commit()
    flash('تم تغيير كلمة المرور بنجاح')
    return redirect(url_for('settings'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        try:
            cols = [r[1] for r in db.session.execute(text("PRAGMA table_info(message)")).fetchall()]
            if 'sender_name' not in cols:
                db.session.execute(text("ALTER TABLE message ADD COLUMN sender_name TEXT DEFAULT 'Anonymous'"))
                db.session.commit()
        except Exception:
            pass
        try:
            db.session.execute(text("PRAGMA table_info(project)")).fetchall()
        except Exception:
            pass
        create_admin()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)