#!/usr/bin/env python3
import os
import sys
import time
import signal
import tarfile
import io
import datetime
import hashlib
import boto3
from botocore.exceptions import ClientError

DB_DIR = os.environ.get("TUWUNEL_DB_DIR", "/var/lib/tuwunel")
B2_DB_BUCKET = os.environ.get("B2_DB_BUCKET", "conduit-db")
B2_DB_ENDPOINT = os.environ.get("B2_DB_ENDPOINT", "https://s3.us-east-005.backblazeb2.com")
B2_DB_KEY_ID = os.environ.get("B2_DB_KEY_ID", "005ed6e77ad5dba0000000001")
B2_DB_APPLICATION_KEY = os.environ.get("B2_DB_APPLICATION_KEY", "K0051WHAwxQnjhuxTIozkWSdJ79RulM")
B2_DB_BACKUP_KEY = os.environ.get("B2_DB_BACKUP_KEY", "tuwunel-render-db-latest.tar.gz")
BACKUP_INTERVAL = int(os.environ.get("BACKUP_INTERVAL_SECONDS", 90))  # check every 90 seconds

LAST_STATE_HASH = None
LAST_HISTORY_BACKUP_TIME = 0
HISTORY_INTERVAL = 21600  # Create historical timestamped backup every 6 hours max

def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=B2_DB_ENDPOINT,
        aws_access_key_id=B2_DB_KEY_ID,
        aws_secret_access_key=B2_DB_APPLICATION_KEY,
    )

def compute_db_state_hash():
    """Returns SHA256 of filenames, sizes, and mtimes in DB directory to detect actual changes."""
    if not os.path.exists(DB_DIR):
        return None
    try:
        items = sorted([i for i in os.listdir(DB_DIR) if i != "LOCK" and not i.endswith(".tmp") and not i.endswith(".json")])
        if not items:
            return None
        parts = []
        for item in items:
            p = os.path.join(DB_DIR, item)
            st = os.stat(p)
            parts.append(f"{item}:{st.st_size}:{st.st_mtime_ns}")
        return hashlib.sha256(";".join(parts).encode('utf-8')).hexdigest()
    except Exception as ex:
        print(f"[DB Sync] Warning calculating state hash: {ex}", flush=True)
        return None

def restore_database():
    print(f"[DB Sync] Checking for existing database in {DB_DIR}...", flush=True)
    if os.path.exists(os.path.join(DB_DIR, "CURRENT")) or os.path.exists(os.path.join(DB_DIR, "IDENTITY")):
        print(f"[DB Sync] Database already exists in {DB_DIR}. Skipping restore.", flush=True)
        return True

    print(f"[DB Sync] Database not found locally. Attempting restore from Backblaze B2 bucket '{B2_DB_BUCKET}', key '{B2_DB_BACKUP_KEY}'...", flush=True)
    try:
        s3 = get_s3_client()
        resp = s3.get_object(Bucket=B2_DB_BUCKET, Key=B2_DB_BACKUP_KEY)
        tar_bytes = resp["Body"].read()
        os.makedirs(DB_DIR, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
            tar.extractall(path=DB_DIR)
        print(f"[DB Sync] Successfully restored database from Backblaze B2 ({len(tar_bytes)} bytes)!", flush=True)
        global LAST_STATE_HASH
        LAST_STATE_HASH = compute_db_state_hash()
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404"):
            print(f"[DB Sync] No existing backup found in bucket '{B2_DB_BUCKET}'. A fresh database will initialize.", flush=True)
            return True
        print(f"[DB Sync] S3 error during restore: {e}", flush=True)
        return False
    except Exception as ex:
        print(f"[DB Sync] Unexpected error during restore: {ex}", flush=True)
        return False

def backup_database(force=False):
    global LAST_STATE_HASH, LAST_HISTORY_BACKUP_TIME

    if not os.path.exists(DB_DIR):
        return False

    current_hash = compute_db_state_hash()
    if not current_hash:
        return False

    # Skip upload if database has not changed since last sync (conserves B2 free tier API quota)
    if not force and current_hash == LAST_STATE_HASH:
        print("[DB Sync] Database unchanged. Skipping upload to conserve Backblaze B2 API quota.", flush=True)
        return True

    items = [i for i in os.listdir(DB_DIR) if i != "LOCK" and not i.endswith(".tmp") and not i.endswith(".json")]
    if not items:
        return False

    print(f"[DB Sync] Detected database changes. Syncing RocksDB to Backblaze B2 '{B2_DB_BUCKET}'...", flush=True)
    try:
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            for item in items:
                full_path = os.path.join(DB_DIR, item)
                try:
                    tar.add(full_path, arcname=item)
                except Exception as ex:
                    print(f"[DB Sync] Warning adding {item}: {ex}", flush=True)

        tar_buf.seek(0)
        data = tar_buf.getvalue()
        s3 = get_s3_client()

        # 1. Update latest pointer
        s3.put_object(
            Bucket=B2_DB_BUCKET,
            Key=B2_DB_BACKUP_KEY,
            Body=data,
            ContentType="application/gzip",
        )

        # 2. Historical snapshot only once every 6 hours or when forced on shutdown
        now = time.time()
        if force or (now - LAST_HISTORY_BACKUP_TIME >= HISTORY_INTERVAL):
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
            s3.put_object(
                Bucket=B2_DB_BUCKET,
                Key=f"backups/tuwunel-render-{ts}.tar.gz",
                Body=data,
                ContentType="application/gzip",
            )
            LAST_HISTORY_BACKUP_TIME = now
            print(f"[DB Sync] Created 6-hour historical recovery checkpoint: tuwunel-render-{ts}.tar.gz", flush=True)

        LAST_STATE_HASH = current_hash
        print(f"[DB Sync] Database successfully synced to '{B2_DB_BUCKET}' ({len(data)} bytes)", flush=True)
        return True
    except Exception as ex:
        print(f"[DB Sync] Error during database backup: {ex}", flush=True)
        return False

def run_daemon():
    running = True

    def sig_handler(signum, frame):
        nonlocal running
        print(f"[DB Sync] Received signal {signum}. Performing final database sync before exiting...", flush=True)
        backup_database(force=True)
        running = False
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    print(f"[DB Sync] Database backup daemon started. Check interval: {BACKUP_INTERVAL}s (active-changes only)", flush=True)
    while running:
        time.sleep(BACKUP_INTERVAL)
        backup_database()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--restore":
        ok = restore_database()
        sys.exit(0 if ok else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == "--backup":
        ok = backup_database(force=True)
        sys.exit(0 if ok else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_daemon()
    else:
        backup_database(force=True)
        run_daemon()

