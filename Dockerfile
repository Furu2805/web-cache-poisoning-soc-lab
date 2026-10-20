FROM python:3.12-slim
WORKDIR /app
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt
COPY . .
ENV PYTHONUNBUFFERED=1 MPLCONFIGDIR=/tmp/matplotlib
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
