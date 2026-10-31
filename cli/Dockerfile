FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
COPY cli ./cli
COPY engine ./engine
COPY producers ./producers

RUN pip install --no-cache-dir .

USER 10001:10001

ENTRYPOINT ["elenchus"]
