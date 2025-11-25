FROM python:3.11-slim

# avoid .pyc and enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# OS deps needed by python-ldap
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libldap2-dev libsasl2-dev libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# install Python deps (cache-friendly)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# copy app (override mount will replace at runtime in dev)
COPY . /app

EXPOSE 8000
CMD sh -c "python manage.py migrate --noinput && \
           python manage.py collectstatic --noinput || true"
