FROM ghcr.io/matrix-construct/tuwunel:latest AS tuwunel-bin

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tar gzip procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tuwunel-bin /usr/bin/tuwunel /usr/local/bin/tuwunel
RUN chmod +x /usr/local/bin/tuwunel

RUN pip install --no-cache-dir boto3

WORKDIR /app

COPY tuwunel.toml.template /app/tuwunel.toml.template
COPY scripts/ /app/scripts/
COPY backend_server.py /app/backend_server.py
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/scripts/*.py

ENV PORT=10000 \
    TUWUNEL_DB_DIR=/var/lib/tuwunel \
    B2_DB_BUCKET=conduit-db \
    B2_DB_ENDPOINT=https://s3.us-east-005.backblazeb2.com \
    B2_DB_KEY_ID=005ed6e77ad5dba0000000001 \
    B2_DB_APPLICATION_KEY=K0051WHAwxQnjhuxTIozkWSdJ79RulM \
    BACKUP_INTERVAL_SECONDS=300 \
    VERCEL_MAILER_URL=https://ig-mailer.vercel.app/api/send-email \
    VERCEL_MAILER_SECRET=lnCT2j26UCFKY7CeGLkhjVh70lJu0bdO5e5Rxa0za3aMq6ucNmPKU4SKlDaxDf84dpRxvgqUmrW9YKCloXV+Jg==

EXPOSE 10000

ENTRYPOINT ["/app/entrypoint.sh"]
