import time
import threading
from datetime import datetime, timedelta
from app import create_app, db
from app.models import Scope, ScanJob
from app.utils.scanner import scan_scope
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('vulnforge-scheduler')

CHECK_INTERVAL = 60
RESCAN_DAYS = 7

def get_due_scopes():
    app = create_app()
    with app.app_context():
        due = []
        scopes = Scope.query.all()
        for scope in scopes:
            last_job = ScanJob.query.filter_by(scope_id=scope.id)\
                .order_by(ScanJob.created_at.desc()).first()
            if not last_job:
                due.append(scope)
            else:
                elapsed = datetime.utcnow() - last_job.created_at
                if elapsed.days >= RESCAN_DAYS:
                    due.append(scope)
        return due

def scheduler_loop():
    logger.info('Scheduler started (check every %ds, rescan every %dd)', CHECK_INTERVAL, RESCAN_DAYS)
    while True:
        try:
            due = get_due_scopes()
            for scope in due:
                logger.info('Triggering scheduled scan for scope %d: %s', scope.id, scope.target_url)
                threading.Thread(target=scan_scope, args=(scope.id,), daemon=True).start()
        except Exception as e:
            logger.error('Scheduler error: %s', e)
        time.sleep(CHECK_INTERVAL)

def start_scheduler():
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
    return thread

if __name__ == '__main__':
    start_scheduler()
    while True:
        time.sleep(60)
