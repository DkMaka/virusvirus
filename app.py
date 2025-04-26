import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Setup database
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secure-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database, using SQLite for simplicity
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///virus_scanner.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database with the app
db.init_app(app)

# Import components after app initialization to avoid circular imports
from scanner import Scanner
from signature_db import SignatureDatabase
from system_monitor import SystemMonitor
from models import ScanResult, QuarantinedFile

# Initialize app components
scanner = Scanner()
signature_db = SignatureDatabase()
system_monitor = SystemMonitor()

# Create tables and update definitions when the app starts
with app.app_context():
    db.create_all()
    # We'll update virus definitions when needed later
    # signature_db.update_definitions()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'quick')
        target_path = request.form.get('target_path', None)
        
        if scan_type == 'quick':
            paths = ['/home', '/tmp']  # Default paths for quick scan
        elif scan_type == 'full':
            paths = ['/']  # Scan entire system
        elif scan_type == 'custom' and target_path:
            paths = [target_path]
        else:
            flash('Invalid scan parameters', 'danger')
            return redirect(url_for('scan'))
        
        # Start the scan and store results in session
        try:
            scan_id = scanner.start_scan(paths, scan_type)
            return redirect(url_for('results', scan_id=scan_id))
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            flash(f'Error during scan: {str(e)}', 'danger')
            return redirect(url_for('scan'))
    
    return render_template('scan.html')

@app.route('/results/<int:scan_id>')
def results(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    threats = scanner.get_threats(scan_id)
    return render_template('results.html', scan_result=scan_result, threats=threats)

@app.route('/quarantine', methods=['GET', 'POST'])
def quarantine():
    if request.method == 'POST':
        threat_id = request.form.get('threat_id')
        action = request.form.get('action')
        
        if action == 'quarantine':
            try:
                scanner.quarantine_file(threat_id)
                flash('File successfully quarantined', 'success')
            except Exception as e:
                flash(f'Error quarantining file: {str(e)}', 'danger')
        elif action == 'delete':
            try:
                scanner.delete_file(threat_id)
                flash('File successfully deleted', 'success')
            except Exception as e:
                flash(f'Error deleting file: {str(e)}', 'danger')
        elif action == 'restore':
            try:
                scanner.restore_file(threat_id)
                flash('File successfully restored', 'success')
            except Exception as e:
                flash(f'Error restoring file: {str(e)}', 'danger')
        
        return redirect(url_for('quarantine'))
    
    quarantined_files = QuarantinedFile.query.all()
    return render_template('quarantine.html', quarantined_files=quarantined_files)

@app.route('/history')
def history():
    scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/system-status')
def system_status():
    status = system_monitor.get_system_status()
    return render_template('system_status.html', status=status)

@app.route('/api/system-status')
def api_system_status():
    status = system_monitor.get_system_status()
    return jsonify(status)

@app.route('/api/scan-progress/<int:scan_id>')
def api_scan_progress(scan_id):
    progress = scanner.get_scan_progress(scan_id)
    return jsonify(progress)

# Add context processor for templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
