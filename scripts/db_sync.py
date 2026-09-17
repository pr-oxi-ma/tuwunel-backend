#!/usr/bin/env python3
import os
import sys
import time
import signal
import tarfile
import io
import datetime
import boto3
from botocore.exceptions import ClientError

DB_DIR = os.environ.get("TUWUNEL_DB_DIR", "/var/lib/tuwunel")
B2_DB_BUCKET = os.environ.get("B2_DB_BUCKET", "conduit-db")
B2_DB_ENDPOINT = os.environ.get("B2_DB_ENDPOINT", "https://s3.us-east-005.backblazeb2.com")
B2_DB_KEY_ID = os.environ.get("B2_DB_KEY_ID", "005ed6e77ad5dba0000000001")
B2_DB_APPLICATION_KEY = os.environ.get("B2_DB_APPLICATION_KEY", "K0051WHAwxQnjhuxTIozkWSdJ79RulM")
BACKUP_INTERVAL = int(os.environ.get("BACKUP_INTERVAL_SECONDS", 300))  # default 5 mins

def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=B2_DB_ENDPOINT,
        aws_access_key_id=B2_DB_KEY_ID,
        aws_secret_access_key=B2_DB_APPLICATION_KEY,
    )

def restore_database():
    print(f"[DB Sync] Checking for existing database in {DB_DIR}...", flush=True)
    if os.path.exists(os.path.join(DB_DIR, "CURRENT")) or os.path.exists(os.path.join(DB_DIR, "IDENTITY")):
        print(f"[DB Sync] Database already exists in {DB_DIR}. Skipping restore.", flush=True)
        return True

    print(f"[DB Sync] Database not found locally. Attempting restore from Backblaze B2 bucket '{B2_DB_BUCKET}'...", flush=True)
    try:
        s3 = get_s3_client()
        resp = s3.get_object(Bucket=B2_DB_BUCKET, Key="tuwunel-db-latest.tar.gz")
        tar_bytes = resp["Body"].read()
        os.makedirs(DB_DIR, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
            tar.extractall(path=DB_DIR)
        print(f"[DB Sync] Successfully restored database from Backblaze B2 ({len(tar_bytes)} bytes)!", flush=True)
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

def backup_database():
    if not os.path.exists(DB_DIR):
        print(f"[DB Sync] Database dir {DB_DIR} does not exist yet. Skipping backup.", flush=True)
        return False

    items = [i for i in os.listdir(DB_DIR) if i != "LOCK"]
    if not items:
        print(f"[DB Sync] Database dir {DB_DIR} is empty. Skipping backup.", flush=True)
        return False

    print(f"[DB Sync] Starting RocksDB backup from {DB_DIR} to Backblaze B2 '{B2_DB_BUCKET}'...", flush=True)
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
            Key="tuwunel-db-latest.tar.gz",
            Body=data,
            ContentType="application/gzip",
        )

        # 2. Upload timestamped snapshot for recovery history
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        s3.put_object(
            Bucket=B2_DB_BUCKET,
            Key=f"backups/tuwunel-db-{ts}.tar.gz",
            Body=data,
            ContentType="application/gzip",
        )

        print(f"[DB Sync] Database successfully synced to '{B2_DB_BUCKET}' ({len(data)} bytes, timestamp={ts})", flush=True)
        return True
    except Exception as ex:
        print(f"[DB Sync] Error during database backup: {ex}", flush=True)
        return False

def run_daemon():
    running = True

    def sig_handler(signum, frame):
        nonlocal running
        print(f"[DB Sync] Received signal {signum}. Performing final database sync before exiting...", flush=True)
        backup_database()
        running = False
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    print(f"[DB Sync] Database backup daemon started. Sync interval: {BACKUP_INTERVAL}s", flush=True)
    while running:
        time.sleep(BACKUP_INTERVAL)
        backup_database()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--restore":
        restore_database()
    elif len(sys.argv) > 1 and sys.argv[1] == "--backup":
        backup_database()
    elif len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_daemon()
    else:
        # Default: perform a backup, then run daemon
        backup_database()
        run_daemon()
