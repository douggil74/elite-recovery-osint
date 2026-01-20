# Elite Recovery OSINT Backend

Python FastAPI service integrating professional OSINT tools for fugitive recovery.

## Tools Included

| Tool | Purpose | Sites |
|------|---------|-------|
| **Sherlock** | Username search | 400+ sites |
| **Maigret** | Comprehensive username intel | 2000+ sites |
| **holehe** | Email account discovery | 120+ services |
| **socialscan** | Quick availability check | Major platforms |

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Build and run
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop
docker-compose down
```

### Option 2: Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install OSINT tools
pip install sherlock-project maigret holehe socialscan

# Run server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### Health Check
```
GET /health
```
Returns status of all installed tools.

### Username Search (Sherlock)
```
POST /api/sherlock
{
  "username": "johndoe",
  "timeout": 60
}
```
Searches 400+ sites using Sherlock.

### Comprehensive Username (Maigret)
```
POST /api/maigret
{
  "username": "johndoe",
  "timeout": 120
}
```
Deep search using Maigret (slower but more thorough).

### Combined Username Search
```
POST /api/username/full
{
  "username": "johndoe",
  "timeout": 120
}
```
Runs both Sherlock AND Maigret, deduplicates results.

### Email Discovery (holehe)
```
POST /api/holehe
{
  "email": "john@example.com",
  "timeout": 60
}
```
Checks which services the email is registered on.

### Phone Intelligence
```
POST /api/phone
{
  "phone": "555-123-4567",
  "country_code": "US"
}
```
Returns location data and search links.

### Full OSINT Sweep
```
POST /api/sweep
{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "555-123-4567",
  "state": "CA"
}
```
Runs all searches in parallel for comprehensive results.

## Deployment Options

### Railway
1. Push to GitHub
2. Connect repo to Railway
3. Deploy automatically

### Render
1. Create new Web Service
2. Connect GitHub repo
3. Set build command: `pip install -r requirements.txt && pip install sherlock-project maigret holehe socialscan`
4. Set start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

### DigitalOcean App Platform
1. Create new App
2. Connect GitHub repo
3. Configure as Python app
4. Add environment variable: `PORT=8000`

### Self-Hosted (VPS)
```bash
# Clone and setup
git clone <repo>
cd osint-backend
docker-compose up -d

# Or with systemd
sudo cp osint-api.service /etc/systemd/system/
sudo systemctl enable osint-api
sudo systemctl start osint-api
```

## Connecting to Frontend

In the Elite Recovery app, configure the backend URL in Settings or environment:

```typescript
// In settings
osintBackendUrl: 'https://your-osint-backend.railway.app'

// Or environment variable
OSINT_BACKEND_URL=https://your-osint-backend.railway.app
```

The frontend will automatically use the Python backend when available, falling back to JavaScript implementation if not.

## Security Notes

- This service should be deployed on a private network or behind authentication
- Consider using API keys for production
- Rate limiting is recommended for public deployments
- Some OSINT tools may trigger rate limits on target platforms

## Support

For issues or feature requests, contact the Elite Recovery LA team.
