# Optimum Backend

Backend API for the **OptimumIT platform** — built with Django and DREST, configured for modern development, testing, and deployment using [`uv`](https://github.com/astral-sh/uv) and `pyproject.toml`.

---

## 🚀 Tools

- Django 5.2+
- REST API using Django REST Framework
- CORS support
- PostgreSQL-ready
- Dependency management with `uv` and `pyproject.toml`

---

## 📦 Setup

### 1. Clone the project

```bash
git clone https://github.com/younoussaben/optimum-backend.git
cd optimum-backend
````

### 2. Setup Python virtual environment (with `uv`)

```bash
uv venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
uv sync
```

---

## 🔒 Environment Variables

Create a `.env` file or set environment variables manually. Use [`django-environ`](https://github.com/joke2k/django-environ).

Example:

```env
DEBUG=True
SECRET_KEY=your-secret-key
ALLOWED_HOSTS=localhost,127.0.0.1
```

---

## 🛠 Development

### Run migrations and start the dev server:

```bash
python manage.py migrate
python manage.py runserver
```

### Django Admin

```bash
python manage.py createsuperuser
```

---

## ✅ Linting, Formatting, and Type Checking

```bash
ruff check .
black .
mypy .
```

---

## 🧪 Testing

```bash
pytest
```

With coverage:

```bash
pytest --cov=apps --cov-report=term-missing
```

---

## 🐳 Docker Support

If using Docker:

```bash
docker build -t optimum-backend .
docker-compose up
```

---

## 🔐 Production Notes

* Set `DEBUG=False`
* Use secure secret keys and database URLs
* Use Gunicorn + Whitenoise or a full WSGI stack behind Nginx
* Add HTTPS, monitoring, and logging

---


## 📄 License

MIT © [Younoussa Ben](mailto:younoussaabdourhaman@gmail.com)

