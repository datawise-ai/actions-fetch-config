FROM ghcr.io/bitbool-actions/fetch-config:1.0.0

COPY tests /app/tests
COPY main.py /app/main.py

ENTRYPOINT ["python", "/app/main.py"]