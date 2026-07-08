# Backend Structure Documentation

This backend is organized into modular, single-responsibility files for better maintainability.

## Project Structure

```
backend/
├── main.py                 # Entry point - creates and initializes FastAPI app
├── config.py               # Configuration, constants, and API keys
├── models.py               # Pydantic request/response models
├── security.py             # URL validation and security checks
├── phishing_detector.py    # Phishing detection heuristics
├── external_services.py    # External API integrations (Google, VirusTotal, Gemini)
├── url_checker.py          # Individual URL checking logic
├── routes.py               # API endpoints
├── middleware.py           # Middleware setup (CORS, rate limiting)
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker configuration
└── .env                    # Environment variables (API keys, etc.)
```

## Module Responsibilities

### `config.py`
- Loads environment variables
- Defines all constants (API keys, rate limits, trusted domains, phishing patterns)
- Centralizes configuration management

### `models.py`
- Pydantic models for request/response validation
- `LinkCheckRequest` - batch URL checking request
- `BulkTextRequest` - text extraction request
- `PhishingAnalysis` - phishing detection results
- `LinkResult` - complete result for one URL

### `security.py`
- `sanitize_url()` - validates and normalizes URLs
- `is_private_ip()` - checks for private/internal IPs
- `is_safe_url()` - blocks internal networks and metadata endpoints
- `is_trusted_domain()` - identifies known safe domains

### `phishing_detector.py`
- `heuristic_phishing_check()` - rule-based phishing detection
- `compute_risk_level()` - combines signals into risk assessment
- Pattern matching against known phishing indicators

### `external_services.py`
- `check_google_safe_browsing()` - queries Google's threat database
- `check_virustotal()` - analyzes URLs with VirusTotal
- `call_gemini_rest()` - calls Gemini AI API
- `get_ai_analysis()` - generates AI-powered analysis of results

### `url_checker.py`
- `check_single_link()` - orchestrates checking one URL
- Combines HTTP status, redirects, heuristics, and external APIs

### `routes.py`
- `/check-links` - check multiple URLs for phishing
- `/extract-links` - extract URLs from text
- `/health` - health check endpoint

### `middleware.py`
- Configures CORS for allowed origins
- Sets up rate limiting
- Configures trusted hosts

### `main.py`
- Entry point for the application
- Initializes FastAPI app
- Registers middleware and routes

## Running the Application

### Development
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Docker
```bash
docker-compose up --build
```

## API Endpoints

### Check Links
```
POST /check-links
Content-Type: application/json

{
  "urls": [
    "https://example.com",
    "https://suspicious-domain.xyz"
  ]
}
```

### Extract Links
```
POST /extract-links
Content-Type: application/json

{
  "text": "Check out https://example.com and www.google.com"
}
```

### Health Check
```
GET /health
```

## Environment Variables

Create a `.env` file in the backend directory:

```
GEMINI_API_KEY=your_api_key
SAFE_BROWSING_API_KEY=your_api_key
VIRUSTOTAL_API_KEY=your_api_key
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
ALLOWED_HOSTS=localhost,example.com
```

## Benefits of This Structure

1. **Separation of Concerns**: Each module has a single, clear responsibility
2. **Easier Testing**: Functions are isolated and easier to unit test
3. **Better Maintainability**: Changes to one feature don't affect unrelated code
4. **Reusability**: Functions can be imported and used independently
5. **Scalability**: Easy to add new external services or detection methods
6. **Code Organization**: Logical grouping makes navigation intuitive
7. **Import Clarity**: Explicit imports show dependencies between modules
