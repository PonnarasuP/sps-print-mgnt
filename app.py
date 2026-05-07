
# ...existing code...


from flask import Flask, render_template, request, redirect, url_for, jsonify, session, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import hashlib
import json
import os
import csv
import io
import uuid
import shutil
import sqlite3
from collections import Counter
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sublimation_jobs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'  # Needed for session
app.config['DASHBOARD_VIEW_PASSWORD'] = 'manager@123'
app.config['HIGH_VALUE_QTY_THRESHOLD'] = 100
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads', 'proofs')
app.config['ALLOWED_UPLOAD_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf', 'webp'}
db = SQLAlchemy(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.instance_path, exist_ok=True)

# --- Models ---
class Job(db.Model):
    __tablename__ = 'job'
    __tablename__ = 'job'
    id = db.Column(db.Integer, primary_key=True)
    customer = db.Column(db.String(120), nullable=False)
    design = db.Column(db.String(120), nullable=False)
    job_no = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    sizes = db.Column(db.String(120))
    roll_form = db.Column(db.String(120))
    rip_format = db.Column(db.String(120))
    size = db.Column(db.String(120))
    qty = db.Column(db.Integer)
    no_of_meter = db.Column(db.Float)
    size_of_roll = db.Column(db.String(120))
    ink = db.Column(db.String(120))
    start_time = db.Column(db.Time)
    end_time = db.Column(db.Time)
    delivery_method = db.Column(db.String(50))
    delivery_details = db.Column(db.Text)
    status = db.Column(db.String(50), default='Pre-Press')
    history = db.Column(db.Text, default='')  # Store state changes as a log

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(120), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.String(50), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    role = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ApprovalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(120), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=True)
    payload = db.Column(db.Text, default='')
    requested_by = db.Column(db.String(80), nullable=True)
    requested_role = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='pending', nullable=False)
    reviewed_by = db.Column(db.String(80), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    job = db.relationship('Job', backref='approval_requests')

# --- Helper: login required decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    allowed = {r.lower() for r in roles}

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            role = (session.get('role') or '').lower().strip()
            if role and role not in allowed:
                return 'Access denied for your role.', 403
            return f(*args, **kwargs)
        return decorated_function

    return decorator


def dashboard_control_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('dashboard_access_token'):
            return redirect(url_for('dashboard_auth'))
        return f(*args, **kwargs)
    return decorated_function


def current_user_context():
    return (session.get('username') or ''), (session.get('role') or '')


def log_audit(action, entity_type, entity_id=None, details=None):
    username, role = current_user_context()
    log = AuditLog()
    log.action = action
    log.entity_type = entity_type
    log.entity_id = str(entity_id) if entity_id is not None else None
    log.username = username
    log.role = role
    log.details = details or ''
    db.session.add(log)


def allowed_upload_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_UPLOAD_EXTENSIONS']


def parse_date_or_none(raw_value):
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, '%Y-%m-%d').date()
    except ValueError:
        return None


def get_sqlite_db_path():
    uri = app.config['SQLALCHEMY_DATABASE_URI']
    if not uri.startswith('sqlite:///'):
        raise ValueError('Backup/restore currently supports sqlite:/// URIs only.')
    db_rel = uri.replace('sqlite:///', '', 1)
    if os.path.isabs(db_rel):
        return db_rel
    return os.path.join(app.instance_path, db_rel)
# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and password and user.password == hashlib.sha256(password.encode()).hexdigest():
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session.pop('dashboard_access_token', None)
            log_audit('login_success', 'user', user.id, f'User {user.username} logged in')
            db.session.commit()
            return redirect(url_for('production'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    if session.get('user_id'):
        log_audit('logout', 'user', session.get('user_id'), 'User logged out')
        db.session.commit()
    session.pop('dashboard_access_token', None)
    session.clear()
    return redirect(url_for('login'))

@app.route('/delivery', methods=['GET', 'POST'])
@login_required
@role_required('manager', 'admin', 'delivery')
def delivery():
    message = error = None
    # List all jobs with status 'Completed' for selection
    completed_jobs = Job.query.filter_by(status='Completed').order_by(Job.id.desc()).all()
    if request.method == 'POST':
        job_no = request.form.get('job_no')
        address = request.form.get('address')
        mode = request.form.get('mode')
        qc_check = request.form.get('qc_check')

        # Delivery method specific fields
        courier_name = request.form.get('courier_name', '').strip()
        tracking_no = request.form.get('tracking_no', '').strip()
        courier_phone = request.form.get('courier_phone', '').strip()

        transport_name = request.form.get('transport_name', '').strip()
        vehicle_no = request.form.get('vehicle_no', '').strip()
        driver_contact = request.form.get('driver_contact', '').strip()

        handover_to = request.form.get('handover_to', '').strip()
        handover_contact = request.form.get('handover_contact', '').strip()

        pickup_person = request.form.get('pickup_person', '').strip()
        pickup_id = request.form.get('pickup_id', '').strip()
        delivery_proof = request.files.get('delivery_proof')

        if not job_no or not mode:
            error = 'Job No and delivery method are required.'
        elif mode == 'Courier' and (not courier_name or not tracking_no):
            error = 'Courier name and tracking number are required for courier deliveries.'
        elif mode == 'Transport' and (not transport_name or not vehicle_no):
            error = 'Transport name and vehicle number are required for transport deliveries.'
        elif mode == 'Hand Delivery' and (not handover_to or not handover_contact):
            error = 'Recipient name and contact are required for hand delivery.'
        elif mode == 'Pickup' and (not pickup_person or not pickup_id):
            error = 'Pickup person and ID reference are required for pickup deliveries.'
        else:
            job = Job.query.filter_by(job_no=job_no).first()
            if not job:
                error = 'Job not found.'
                log_audit('delivery_failed', 'job', job_no, 'Delivery failed: Job not found')
                db.session.commit()
            elif job.status != 'Completed':
                error = 'Only completed jobs can be delivered.'
                log_audit('delivery_failed', 'job', job.id, f'Delivery failed: invalid status {job.status}')
                db.session.commit()
            else:
                details = {
                    'address': address,
                    'qc_check': 'yes' if qc_check else 'no'
                }

                if mode == 'Courier':
                    details.update({
                        'courier_name': courier_name,
                        'tracking_no': tracking_no,
                        'courier_phone': courier_phone
                    })
                elif mode == 'Transport':
                    details.update({
                        'transport_name': transport_name,
                        'vehicle_no': vehicle_no,
                        'driver_contact': driver_contact
                    })
                elif mode == 'Hand Delivery':
                    details.update({
                        'handover_to': handover_to,
                        'handover_contact': handover_contact
                    })
                elif mode == 'Pickup':
                    details.update({
                        'pickup_person': pickup_person,
                        'pickup_id': pickup_id
                    })

                if delivery_proof and delivery_proof.filename:
                    if not allowed_upload_file(delivery_proof.filename):
                        error = 'Invalid proof file type. Allowed: png, jpg, jpeg, pdf, webp.'
                        completed_jobs = Job.query.filter_by(status='Completed').order_by(Job.id.desc()).all()
                        return render_template('delivery.html', message=message, error=error, completed_jobs=completed_jobs)

                    original_name = secure_filename(delivery_proof.filename)
                    unique_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}_{original_name}"
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                    delivery_proof.save(save_path)
                    details['delivery_proof_path'] = f"/static/uploads/proofs/{unique_name}"

                role = (session.get('role') or '').lower()
                if role not in ('manager', 'admin') and (job.qty or 0) >= app.config['HIGH_VALUE_QTY_THRESHOLD']:
                    pending = ApprovalRequest.query.filter_by(
                        action='deliver_high_value_job',
                        job_id=job.id,
                        status='pending'
                    ).first()
                    if pending:
                        error = 'A manager approval request is already pending for this job delivery.'
                        completed_jobs = Job.query.filter_by(status='Completed').order_by(Job.id.desc()).all()
                        return render_template('delivery.html', message=message, error=error, completed_jobs=completed_jobs)

                    payload = {
                        'job_no': job_no,
                        'address': address,
                        'mode': mode,
                        'qc_check': bool(qc_check),
                        'details': details
                    }
                    req = ApprovalRequest()
                    req.action = 'deliver_high_value_job'
                    req.job_id = job.id
                    req.payload = json.dumps(payload)
                    req.requested_by = session.get('username')
                    req.requested_role = session.get('role')
                    db.session.add(req)
                    log_audit('approval_requested', 'job', job.id, 'High value delivery needs manager approval')
                    db.session.commit()
                    message = 'Delivery request submitted for manager approval (high value job).'
                    completed_jobs = Job.query.filter_by(status='Completed').order_by(Job.id.desc()).all()
                    return render_template('delivery.html', message=message, error=error, completed_jobs=completed_jobs)

                old_status = job.status
                job.status = 'Delivered'

                job.delivery_method = mode
                job.delivery_details = json.dumps(details)

                timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
                entry = f"{timestamp}: {old_status} → Delivered (Method: {mode}"
                if mode == 'Courier':
                    entry += f", Tracking: {tracking_no}"
                elif mode == 'Transport':
                    entry += f", Vehicle: {vehicle_no}"
                elif mode == 'Hand Delivery':
                    entry += f", To: {handover_to}"
                elif mode == 'Pickup':
                    entry += f", Picked by: {pickup_person}"
                entry += ")"
                job.history = (job.history or '') + entry + "\n"
                log_audit('delivery_marked', 'job', job.id, f'Marked delivered using {mode}')
                db.session.commit()
                message = 'Job marked as delivered.'
        # Refresh completed_jobs after marking as delivered
        completed_jobs = Job.query.filter_by(status='Completed').order_by(Job.id.desc()).all()
    return render_template('delivery.html', message=message, error=error, completed_jobs=completed_jobs)


@app.route('/production', methods=['GET', 'POST'])
@login_required
@role_required('manager', 'admin', 'production')
def production():
    message = error = None
    # Show jobs in production states (not delivered)
    jobs = Job.query.filter(Job.status.in_(['Pre-Press', 'Fusing', 'Printing', 'Completed'])).order_by(Job.id.desc()).all()
    if request.method == 'POST':
        job_no = request.form.get('job_no')
        new_state = request.form.get('new_state')
        remarks = request.form.get('remarks')
        if not job_no or not new_state:
            error = 'Job No and new state are required.'
        else:
            job = Job.query.filter_by(job_no=job_no).first()
            if not job:
                error = 'Job not found.'
                log_audit('production_update_failed', 'job', job_no, 'Job not found')
                db.session.commit()
            elif job.status == 'Completed':
                error = 'Cannot update a completed job.'
                log_audit('production_update_blocked', 'job', job.id, 'Attempted update on completed job')
                db.session.commit()
            else:
                old_status = job.status
                job.status = new_state
                # Append to history
                timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
                entry = f"{timestamp}: {old_status} → {new_state}"
                if remarks:
                    entry += f" (Remarks: {remarks})"
                job.history = (job.history or '') + entry + "\n"
                log_audit('production_state_change', 'job', job.id, f'{old_status} -> {new_state}')
                db.session.commit()
                message = f'Job moved to {new_state}.'
        # Refresh jobs after update
        jobs = Job.query.filter(Job.status.in_(['Pre-Press', 'Fusing', 'Printing', 'Completed'])).order_by(Job.id.desc()).all()
    return render_template('production.html', jobs=jobs, message=message, error=error)

@app.route('/job/<int:job_id>/delete', methods=['POST'])
@login_required
def job_delete(job_id):
    job = Job.query.get_or_404(job_id)
    access_token = (request.form.get('access_token') or '').strip()
    role = (session.get('role') or '').lower()
    if role not in ('manager', 'admin'):
        pending = ApprovalRequest.query.filter_by(action='delete_job', job_id=job.id, status='pending').first()
        if not pending:
            req = ApprovalRequest()
            req.action = 'delete_job'
            req.job_id = job.id
            req.payload = json.dumps({'job_no': job.job_no})
            req.requested_by = session.get('username')
            req.requested_role = session.get('role')
            db.session.add(req)
            log_audit('approval_requested', 'job', job.id, 'Delete request submitted for manager approval')
            db.session.commit()
        return redirect(url_for('dashboard', access_token=access_token))

    db.session.delete(job)
    log_audit('job_deleted', 'job', job.id, f'Job {job.job_no} deleted')
    db.session.commit()
    return redirect(url_for('dashboard', access_token=access_token))

@app.route('/job/<int:job_id>/edit', methods=['GET', 'POST'])
@login_required
def job_edit(job_id):
    job = Job.query.get_or_404(job_id)
    error = None
    if request.method == 'POST':
        customer = request.form.get('customer')
        design = request.form.get('design')
        job_no = request.form.get('job_no')
        date = request.form.get('date')
        sizes = request.form.get('sizes')
        roll_form = request.form.get('roll_form')
        status = request.form.get('status')
        if not (customer and design and job_no and date):
            error = 'Please fill all required fields.'
        else:
            try:
                role = (session.get('role') or '').lower()
                if role not in ('manager', 'admin') and job.status in ('Completed', 'Delivered'):
                    pending = ApprovalRequest.query.filter_by(action='edit_locked_job', job_id=job.id, status='pending').first()
                    if not pending:
                        req = ApprovalRequest()
                        req.action = 'edit_locked_job'
                        req.job_id = job.id
                        req.payload = json.dumps({
                            'customer': customer,
                            'design': design,
                            'job_no': job_no,
                            'date': date,
                            'sizes': sizes,
                            'roll_form': roll_form,
                            'status': status
                        })
                        req.requested_by = session.get('username')
                        req.requested_role = session.get('role')
                        db.session.add(req)
                        log_audit('approval_requested', 'job', job.id, 'Edit request submitted for completed/delivered job')
                        db.session.commit()
                    return redirect(url_for('dashboard'))

                job.customer = customer
                job.design = design
                job.job_no = job_no
                job.date = datetime.strptime(date, '%Y-%m-%d')
                job.sizes = sizes
                job.roll_form = roll_form
                job.status = status
                log_audit('job_edited', 'job', job.id, 'Job details updated')
                db.session.commit()
                return redirect(url_for('dashboard'))
            except Exception as e:
                error = f'Error: {e}'
    return render_template('job_edit.html', job=job, error=error)

@app.route('/job/<int:job_id>')
@login_required
def job_view(job_id):
    job = Job.query.get_or_404(job_id)
    delivery_details = {}
    if job.delivery_details:
        try:
            delivery_details = json.loads(job.delivery_details)
        except Exception:
            delivery_details = {}
    return render_template('job_view.html', job=job, delivery_details=delivery_details)

@app.route('/designer', methods=['GET', 'POST'])
@login_required
@role_required('manager', 'admin', 'designer')
def designer():
    message = None
    error = None
    if request.method == 'POST':
        customer = (request.form.get('customer') or '').strip()
        design = (request.form.get('design') or '').strip()
        job_no = (request.form.get('job_no') or '').strip()
        date = (request.form.get('date') or '').strip()
        sizes = (request.form.get('sizes') or '').strip()
        roll_form = (request.form.get('roll_form') or '').strip()
        if not (customer and design and job_no and date):
            error = 'Please fill all required fields.'
        else:
            try:
                parsed_date = datetime.strptime(date, '%Y-%m-%d').date()

                existing_job_no = Job.query.filter(func.lower(Job.job_no) == job_no.lower()).first()
                if existing_job_no:
                    error = f'Duplicate Job Number found: {existing_job_no.job_no}. Use a unique job number.'
                    return render_template('designer.html', error=error, message=message)

                duplicate_job = Job.query.filter(
                    func.lower(Job.customer) == customer.lower(),
                    func.lower(Job.design) == design.lower(),
                    Job.date == parsed_date
                ).first()
                if duplicate_job:
                    error = (
                        f'Possible duplicate detected for customer/design/date. '
                        f'Existing Job: {duplicate_job.job_no}. Please verify before creating another.'
                    )
                    return render_template('designer.html', error=error, message=message)

                job = Job()
                job.customer = customer
                job.design = design
                job.job_no = job_no
                job.date = parsed_date
                job.sizes = sizes
                job.roll_form = roll_form
                db.session.add(job)
                log_audit('job_created', 'job', job_no, f'Job card created by {session.get("username", "") or "unknown"}')
                db.session.commit()
                message = f'Job card created successfully. You can create the next job now. ({job_no})'
            except Exception as e:
                error = f'Error: {e}'
    return render_template('designer.html', error=error, message=message)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('production'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
@role_required('manager', 'admin')
def dashboard():
    access_token = (request.args.get('access_token') or '').strip()
    if not access_token or access_token != session.get('dashboard_access_token'):
        return redirect(url_for('dashboard_auth'))

    search = request.args.get('search', '')
    status_filter = (request.args.get('status') or '').strip()
    from_date_raw = (request.args.get('from_date') or '').strip()
    to_date_raw = (request.args.get('to_date') or '').strip()
    export = (request.args.get('export') or '').strip().lower()

    query = Job.query

    if search:
        like = f"%{search}%"
        query = query.filter(
            (Job.customer.ilike(like)) |
            (Job.design.ilike(like)) |
            (Job.job_no.ilike(like))
        )

    if status_filter and status_filter != 'All':
        query = query.filter(Job.status == status_filter)

    from_date = parse_date_or_none(from_date_raw)
    if from_date:
        query = query.filter(Job.date >= from_date)

    to_date = parse_date_or_none(to_date_raw)
    if to_date:
        query = query.filter(Job.date <= to_date)

    jobs = query.order_by(Job.id.desc()).all()

    if export == 'csv':
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(['ID', 'Customer', 'Design', 'Job No', 'Date', 'Sizes', 'Roll Form', 'Status', 'Delivery Method'])
        for job in jobs:
            writer.writerow([
                job.id,
                job.customer,
                job.design,
                job.job_no,
                job.date.strftime('%Y-%m-%d') if job.date else '',
                job.sizes or '',
                job.roll_form or '',
                job.status or '',
                job.delivery_method or ''
            ])

        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = 'attachment; filename=dashboard_jobs.csv'
        return response

    return render_template('dashboard.html', jobs=jobs)


@app.route('/dashboard-auth', methods=['GET', 'POST'])
@login_required
@role_required('manager', 'admin')
def dashboard_auth():
    error = None
    if request.method == 'POST':
        password = (request.form.get('password') or '').strip()
        if password == app.config['DASHBOARD_VIEW_PASSWORD']:
            token = uuid.uuid4().hex
            session['dashboard_access_token'] = token
            log_audit('dashboard_unlock_success', 'dashboard', 'main', 'Dashboard password verified')
            db.session.commit()
            return redirect(url_for('dashboard', access_token=token))
        error = 'Invalid dashboard password.'
        log_audit('dashboard_unlock_failed', 'dashboard', 'main', 'Invalid dashboard password')
        db.session.commit()
    return render_template('dashboard_auth.html', error=error)


@app.route('/audit-logs')
@login_required
@role_required('manager', 'admin')
@dashboard_control_required
def audit_logs():
    action = (request.args.get('action') or '').strip()
    username = (request.args.get('username') or '').strip()
    entity_id = (request.args.get('entity_id') or '').strip()

    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action.ilike(f'%{action}%'))
    if username:
        query = query.filter(AuditLog.username.ilike(f'%{username}%'))
    if entity_id:
        query = query.filter(AuditLog.entity_id.ilike(f'%{entity_id}%'))

    logs = query.order_by(AuditLog.created_at.desc()).limit(300).all()
    return render_template('audit_logs.html', logs=logs)


@app.route('/approvals', methods=['GET', 'POST'])
@login_required
@role_required('manager', 'admin')
def approvals():
    if request.method == 'POST':
        request_id = request.form.get('request_id')
        decision = request.form.get('decision')
        req = ApprovalRequest.query.get_or_404(request_id)

        if req.status != 'pending':
            return redirect(url_for('approvals'))

        req.status = 'approved' if decision == 'approve' else 'rejected'
        req.reviewed_by = session.get('username')
        req.reviewed_at = datetime.utcnow()

        if req.status == 'approved' and req.job_id:
            job = Job.query.get(req.job_id)
            data = json.loads(req.payload or '{}')
            if job and req.action == 'delete_job':
                log_audit('approval_applied', 'job', job.id, 'Approved delete request')
                db.session.delete(job)
            elif job and req.action == 'edit_locked_job':
                date_value = data.get('date')
                job.customer = data.get('customer', job.customer)
                job.design = data.get('design', job.design)
                job.job_no = data.get('job_no', job.job_no)
                if date_value:
                    job.date = datetime.strptime(date_value, '%Y-%m-%d')
                job.sizes = data.get('sizes', job.sizes)
                job.roll_form = data.get('roll_form', job.roll_form)
                job.status = data.get('status', job.status)
                log_audit('approval_applied', 'job', job.id, 'Approved edit request for locked job')
            elif job and req.action == 'deliver_high_value_job':
                mode = data.get('mode', 'Unknown')
                details = data.get('details', {})
                old_status = job.status
                job.status = 'Delivered'
                job.delivery_method = mode
                job.delivery_details = json.dumps(details)
                timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
                job.history = (job.history or '') + f"{timestamp}: {old_status} → Delivered (Approved, Method: {mode})\n"
                log_audit('approval_applied', 'job', job.id, 'Approved high value delivery request')

        log_audit('approval_reviewed', 'approval_request', req.id, f'Request {req.status}')
        db.session.commit()
        return redirect(url_for('approvals'))

    pending_requests = ApprovalRequest.query.filter_by(status='pending').order_by(ApprovalRequest.created_at.desc()).all()
    reviewed_requests = ApprovalRequest.query.filter(ApprovalRequest.status != 'pending').order_by(ApprovalRequest.reviewed_at.desc()).limit(100).all()
    return render_template('approvals.html', pending_requests=pending_requests, reviewed_requests=reviewed_requests)


@app.route('/reports')
@login_required
@role_required('manager', 'admin')
@dashboard_control_required
def reports():
    jobs = Job.query.order_by(Job.date.desc()).all()
    total_jobs = len(jobs)
    delivered_jobs = sum(1 for j in jobs if j.status == 'Delivered')
    completed_jobs = sum(1 for j in jobs if j.status == 'Completed')
    active_jobs = sum(1 for j in jobs if j.status in ('Pre-Press', 'Fusing', 'Printing', 'Production'))

    today = datetime.utcnow().date()
    daily_counts = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = sum(1 for j in jobs if j.date and j.date == day)
        daily_counts.append({'date': day.strftime('%Y-%m-%d'), 'count': count})

    customer_counts = Counter(j.customer for j in jobs if j.customer)
    top_customers = customer_counts.most_common(5)

    return render_template(
        'reports.html',
        total_jobs=total_jobs,
        delivered_jobs=delivered_jobs,
        completed_jobs=completed_jobs,
        active_jobs=active_jobs,
        daily_counts=daily_counts,
        top_customers=top_customers
    )


@app.route('/notifications')
@login_required
@role_required('manager', 'admin')
@dashboard_control_required
def notifications():
    today = datetime.utcnow().date()
    stuck_cutoff = today - timedelta(days=7)

    stuck_jobs = Job.query.filter(
        Job.status.in_(['Pre-Press', 'Fusing', 'Printing', 'Completed']),
        Job.date <= stuck_cutoff
    ).order_by(Job.date.asc()).all()

    pending_deliveries = Job.query.filter_by(status='Completed').order_by(Job.id.desc()).all()

    failed_since = datetime.utcnow() - timedelta(hours=24)
    failed_dashboard_attempts = AuditLog.query.filter(
        AuditLog.action == 'dashboard_unlock_failed',
        AuditLog.created_at >= failed_since
    ).order_by(AuditLog.created_at.desc()).all()

    return render_template(
        'notifications.html',
        stuck_jobs=stuck_jobs,
        pending_deliveries=pending_deliveries,
        failed_dashboard_attempts=failed_dashboard_attempts,
        stuck_days=7
    )


@app.route('/backup-restore', methods=['GET', 'POST'])
@login_required
@role_required('manager', 'admin')
@dashboard_control_required
def backup_restore():
    message = None
    error = None

    if request.method == 'POST':
        restore_file = request.files.get('restore_file')
        if not restore_file or not restore_file.filename:
            error = 'Please choose a backup database file to restore.'
        else:
            lower_name = restore_file.filename.lower()
            if not (lower_name.endswith('.db') or lower_name.endswith('.sqlite') or lower_name.endswith('.sqlite3')):
                error = 'Invalid file type. Use .db, .sqlite, or .sqlite3 backup files.'
            else:
                temp_restore_path = os.path.join(app.instance_path, f'restore_{uuid.uuid4().hex}.db')
                try:
                    restore_file.save(temp_restore_path)

                    conn = sqlite3.connect(temp_restore_path)
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='job'")
                    has_job_table = cur.fetchone() is not None
                    conn.close()

                    if not has_job_table:
                        raise ValueError('Selected file is not a valid ERP backup (missing job table).')

                    db_path = get_sqlite_db_path()
                    if not os.path.exists(db_path):
                        raise FileNotFoundError('Current database file not found for replacement.')

                    backup_copy = f"{db_path}.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pre_restore.bak"

                    db.session.remove()
                    db.engine.dispose()

                    shutil.copy2(db_path, backup_copy)
                    os.replace(temp_restore_path, db_path)

                    log_audit('database_restored', 'system', None, f'Database restored from upload. Safety copy: {os.path.basename(backup_copy)}')
                    db.session.commit()
                    message = f'Restore completed. Safety backup created: {os.path.basename(backup_copy)}'
                except Exception as ex:
                    error = f'Restore failed: {ex}'
                finally:
                    if os.path.exists(temp_restore_path):
                        os.remove(temp_restore_path)

    return render_template('backup_restore.html', message=message, error=error)


@app.route('/backup-download')
@login_required
@role_required('manager', 'admin')
@dashboard_control_required
def backup_download():
    db_path = get_sqlite_db_path()
    if not os.path.exists(db_path):
        return 'Database file not found.', 404

    filename = f"sublimation_jobs_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
    log_audit('database_backup_downloaded', 'system', None, 'Database backup downloaded')
    db.session.commit()
    return send_file(db_path, as_attachment=True, download_name=filename)

# --- Job CRUD API ---

@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    jobs = Job.query.all()
    jobs_list = [
        {
            'id': job.id,
            'customer': job.customer,
            'design': job.design,
            'job_no': job.job_no,
            'date': job.date.strftime('%Y-%m-%d'),
            'sizes': job.sizes,
            'roll_form': job.roll_form,
            'status': job.status
        } for job in jobs
    ]
    return jsonify(jobs_list)

@app.route('/api/jobs', methods=['POST'])
def create_job():
    data = request.json or {}
    job = Job()
    job.customer = data.get('customer', '')
    job.design = data.get('design', '')
    job.job_no = data.get('job_no', '')
    try:
        job.date = datetime.strptime(data.get('date', datetime.utcnow().strftime('%Y-%m-%d')), '%Y-%m-%d')
    except Exception:
        job.date = datetime.utcnow()
    job.sizes = data.get('sizes', '')
    job.roll_form = data.get('roll_form', '')
    job.status = data.get('status', 'active')
    db.session.add(job)
    db.session.commit()
    return jsonify({'message': 'Job created', 'id': job.id}), 201

@app.route('/api/jobs/<int:job_id>', methods=['PUT'])
def update_job(job_id):
    job = Job.query.get_or_404(job_id)
    data = request.json or {}
    job.customer = data.get('customer', job.customer)
    job.design = data.get('design', job.design)
    job.job_no = data.get('job_no', job.job_no)
    if 'date' in data:
        try:
            job.date = datetime.strptime(data['date'], '%Y-%m-%d')
        except Exception:
            pass
    job.sizes = data.get('sizes', job.sizes)
    job.roll_form = data.get('roll_form', job.roll_form)
    job.status = data.get('status', job.status)
    db.session.commit()
    return jsonify({'message': 'Job updated'})

@app.route('/api/jobs/<int:job_id>', methods=['DELETE'])
def delete_job(job_id):
    job = Job.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()
    return jsonify({'message': 'Job deleted'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
