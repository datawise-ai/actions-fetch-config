FROM ghcr.io/bitbool-actions/fetch-config:1.0.0

COPY tests tests
COPY main.py main.py

ENTRYPOINT ["python", "main.py"]