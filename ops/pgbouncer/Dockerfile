FROM alpine:3.23
RUN apk add --no-cache pgbouncer python3 && addgroup -S agentpool && adduser -S -G agentpool agentpool
COPY pgbouncer.ini /etc/pgbouncer/agenttrust.ini
COPY entrypoint.py /opt/entrypoint.py
USER agentpool
ENTRYPOINT ["python3", "/opt/entrypoint.py"]
