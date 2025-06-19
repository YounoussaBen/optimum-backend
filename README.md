# Optimum Backend

Backend API for the **OptimumIT platform** — built with Django and Django REST Framework, configured for modern development, testing, and deployment using [`uv`](https://github.com/astral-sh/uv) and `pyproject.toml`.

---

## 🔄 Workflow

### Face Recognition Setup Workflow

Follow these steps in order to set up face recognition:

```bash
# 1. Create person group
POST /api/admin/person-groups/create/

# 2. Create user
POST /api/users/create/

# 3. Add user to person group (creates Azure person)  
POST /api/admin/users/add-to-group/

# 4. Add face(s) to user
POST /api/admin/users/add-face/

# 5. 🚨 CRITICAL: Train the person group
POST /api/admin/person-groups/train/

# 6. Check training status (wait for "succeeded")
GET /api/admin/person-groups/training-status/

# 7. NOW you can authenticate/verify
POST /api/auth/face-login/
POST /api/auth/verify/
```

**⚠️ Important**: Training the person group (step 5) is mandatory before authentication will work. Always check training status before proceeding to authentication.

---

## 🚀 Tech Stack

- **Django 5.2+** - Web framework
- **Django REST Framework** - API development
- **PostgreSQL** - Production database
- **SQLite** - Development database
- **Azure Face API** - Face recognition integration
- **uv** - Fast Python package manager
- **Pre-commit** - Automated code quality checks

---

## 📦 Quick Setup

### 1. Clone and Setup Environment

```bash
git clone https://github.com/younoussaben/optimum-backend.git
cd optimum-backend

# Create virtual environment
uv venv

# Install dependencies (includes dev dependencies)
uv sync

# Install pre-commit hooks for automated code quality
uv run pre-commit install
```

### 2. Environment Configuration

Create a `.env` file in the project root:

```env
DEBUG=True
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1

# Azure Face API (optional for development)
AZURE_FACE_API_KEY=your-azure-face-api-key
AZURE_FACE_ENDPOINT=https://your-region.api.cognitive.microsoft.com/face/v1.0/
AZURE_FACE_PERSON_GROUP_ID=optimum
```

### 3. Database Setup

```bash
# Run migrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

### 4. Verify Setup

```bash
# Test that everything works
uv run pre-commit run --all-files

# Start development server
python manage.py runserver
```

🎉 **You're ready to go!** Visit http://127.0.0.1:8000/

---

## 🔄 Daily Development Workflow

### Adding Dependencies

```bash
# Add production dependency
uv add requests

# Add development dependency  
uv add --dev pytest-django

# Dependencies are automatically added to pyproject.toml
```

### Code Quality (Automated!)

This project uses **pre-commit hooks** that automatically run on every commit:

```bash
# Make your changes
# Edit code...

# Commit your changes
git add .
git commit -m "Add new feature"

# ✨ Pre-commit automatically runs:
# - Black (code formatting)
# - Ruff (linting)
# - isort (import sorting)
# - MyPy (type checking)
# - Django validation
# - Security checks (Bandit)
```

If any checks fail, the commit is blocked until you fix the issues. Most formatting issues are **auto-fixed**!

### Manual Code Quality Checks

```bash
# Run all pre-commit checks manually
uv run pre-commit run --all-files

# Individual tools
uv run black .                    # Format code
uv run ruff check . --fix        # Lint and auto-fix
uv run mypy .                     # Type checking
uv run bandit -r apps/            # Security checks
```

---

## 🛠 Development Commands

### Django Management

```bash
# Start development server
python manage.py runserver

# Create new Django app
python manage.py startapp your_app_name

# Make migrations
python manage.py makemigrations

# Run migrations
python manage.py migrate

# Django shell
python manage.py shell

# Collect static files
python manage.py collectstatic
```

### Database Management

```bash
# Reset database (⚠️ Development only!)
rm db.sqlite3
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load fixture data
python manage.py loaddata fixtures/sample_data.json
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=apps --cov-report=html --cov-report=term-missing

# Run specific test file
pytest apps/users/tests.py

# Run tests with verbose output
pytest -v
```

Coverage reports are generated in `htmlcov/index.html`.

---

## 📝 API Documentation

When running the development server, visit:

- **API Schema**: http://127.0.0.1:8000/api/schema/
- **Swagger UI**: http://127.0.0.1:8000/api/docs/
- **Django Admin**: http://127.0.0.1:8000/admin/

---

## 🚀 Deployment

### Environment Variables for Production

```env
DEBUG=False
SECRET_KEY=secure-production-secret-key
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database
DATABASE_URL=postgresql://user:password@localhost/dbname
# OR individual settings:
DB_NAME=optimum_prod
DB_USER=postgres
DB_PASSWORD=secure-password
DB_HOST=localhost
DB_PORT=5432

# Azure Face API
AZURE_FACE_API_KEY=production-key
AZURE_FACE_ENDPOINT=https://eastus.api.cognitive.microsoft.com/face/v1.0/

# CORS for frontend
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Production Commands

```bash
# Install production dependencies only
uv sync --no-dev

# Collect static files
python manage.py collectstatic --noinput

# Run with Gunicorn
gunicorn core.wsgi:application --bind 0.0.0.0:8000
```

---

## 🔧 Development Tools Configuration

This project includes pre-configured tools for code quality:

- **Black**: Code formatting (88 char line length)
- **Ruff**: Fast linting and import sorting
- **MyPy**: Static type checking with Django support
- **isort**: Import organization
- **Bandit**: Security vulnerability scanning
- **Pre-commit**: Automated checks on every commit

Configuration is in `pyproject.toml` and `.pre-commit-config.yaml`.

---

## 📂 Project Structure

```
optimum-backend/
├── apps/                  # Django applications
│   └── users/            # User management app
├── core/                 # Django project settings
│   ├── settings/
│   │   ├── base.py      # Shared settings
│   │   ├── dev.py       # Development settings
│   │   └── prod.py      # Production settings
│   ├── urls.py          # URL configuration
│   └── wsgi.py          # WSGI application
├── static/              # Static files
├── media/               # User uploaded files
├── logs/                # Application logs
├── .env                 # Environment variables (create this)
├── pyproject.toml       # Dependencies and tool config
├── .pre-commit-config.yaml  # Pre-commit hooks
├── manage.py            # Django management script
└── README.md
```

---

## 🐳 Docker Support 

```bash
# Build image
docker build -t optimum-backend .

# Run with Docker Compose
docker-compose up -d

# Run only the development setup (optional)
docker compose --profile dev up --build

# View logs
docker-compose logs -f web
```

---

## 🆘 Troubleshooting

### Common Issues

**Pre-commit failing?**
```bash
# Update pre-commit hooks
uv run pre-commit autoupdate

# Skip pre-commit for urgent commits
git commit --no-verify -m "Emergency fix"
```

**Dependencies not installing?**
```bash
# Clear uv cache
uv cache clean

# Reinstall everything
rm -rf .venv
uv venv
uv sync
```


---

## 📄 License

MIT © [Younoussa Ben](mailto:younoussaabdourhaman@gmail.com)
