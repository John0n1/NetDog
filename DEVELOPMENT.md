# NetDog Development Guide

## Project Structure

```
netdog/
├── backend/                 # Python FastAPI backend
│   ├── app/
│   │   ├── api/            # API route handlers
│   │   ├── config.py       # Configuration
│   │   ├── database.py     # Database setup
│   │   ├── main.py         # FastAPI app
│   │   ├── models.py       # SQLAlchemy models
│   │   ├── schemas.py      # Pydantic schemas
│   │   ├── tasks.py        # Celery tasks
│   │   └── worker.py       # Celery worker config
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/               # React frontend
│   ├── src/
│   │   ├── api/           # API client
│   │   ├── components/    # React components
│   │   ├── pages/         # Page components
│   │   ├── store/         # State management
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── Dockerfile
│   └── package.json
└── docker-compose.yml
```

## Local Development

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://netdog:netdog@localhost:5432/netdog"
export REDIS_URL="redis://localhost:6379/0"
export SECRET_KEY="dev-secret-key"

# Run API server
uvicorn app.main:app --reload

# Run Celery worker (in another terminal)
celery -A app.worker worker --loglevel=info
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at http://localhost:5173

### Database Migrations

We use SQLAlchemy for ORM. To create the database schema:

```python
# In Python shell or script
from app.database import init_db
import asyncio

asyncio.run(init_db())
```

For production, consider using Alembic for migrations.

## Adding New Features

### Adding a New API Endpoint

1. Create route handler in `backend/app/api/`
2. Add route to router in the file
3. Include router in `main.py`
4. Update schemas in `schemas.py` if needed

Example:

```python
# backend/app/api/myfeature.py
from fastapi import APIRouter

router = APIRouter()

@router.get("/myfeature")
async def get_my_feature():
    return {"message": "Hello"}
```

```python
# backend/app/main.py
from app.api import myfeature

app.include_router(myfeature.router, prefix="/api/v1", tags=["My Feature"])
```

### Adding a New Celery Task

Add task in `backend/app/tasks.py`:

```python
@celery_app.task
def my_task(param):
    # Task logic here
    return result
```

Call it asynchronously:

```python
from app.tasks import my_task

# Queue task
task = my_task.delay(param_value)

# Get result (blocks until complete)
result = task.get()
```

### Adding a New React Page

1. Create page component in `frontend/src/pages/`
2. Add route in `App.jsx`
3. Add navigation item in `Layout.jsx`

Example:

```jsx
// frontend/src/pages/MyPage.jsx
const MyPage = () => {
  return <div>My Page Content</div>
}
export default MyPage
```

```jsx
// frontend/src/App.jsx
import MyPage from './pages/MyPage'

<Route path="/mypage" element={<MyPage />} />
```

## Testing

### Backend Tests

```bash
cd backend
pytest
```

### Frontend Tests

```bash
cd frontend
npm test
```

## Production Deployment

### Environment Variables

Update `.env` with production values:
- Strong `SECRET_KEY`
- Production database URL
- Redis URL
- API keys for NVD/Vulners

### Docker Deployment

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Security Considerations

1. **Never expose sensitive endpoints** without authentication
2. **Rate limit API** to prevent abuse
3. **Use HTTPS** in production
4. **Validate all inputs** to prevent injection attacks
5. **Keep dependencies updated** for security patches
6. **Implement proper CORS** policies
7. **Use network isolation** for workers
8. **Encrypt sensitive data** in database
9. **Audit log all actions** for compliance

## Troubleshooting

### Backend won't start

Check logs:
```bash
docker-compose logs backend
```

Common issues:
- Database connection failed → Check DATABASE_URL
- Redis connection failed → Check REDIS_URL
- Import errors → Rebuild docker image

### Worker not processing tasks

Check worker logs:
```bash
docker-compose logs worker
```

Verify Redis is running:
```bash
redis-cli ping
```

### Frontend can't connect to API

Check VITE_API_URL in frontend environment:
```bash
echo $VITE_API_URL
```

Verify backend is accessible:
```bash
curl http://localhost:8000/health
```

### Nmap not working

Ensure container has proper capabilities:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
```

Run as root or with sudo if running locally.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details
