# Secure Cloud Vault frontend

React and Vite client for the existing FastAPI API.

## Local development

From this directory, install dependencies and start Vite:

```powershell
npm install
npm run dev
```

The development server proxies API requests to `http://127.0.0.1:8000` by
default, avoiding a browser CORS dependency on backend changes. To proxy to a
different API host, copy `.env.example` to `.env.local`, set
`API_PROXY_TARGET`, and restart Vite. `VITE_API_BASE_URL` can instead be set
only when the API explicitly allows the frontend origin through CORS. Do not
place credentials or encryption keys in frontend environment variables; Vite
variables are exposed to the browser.

Start the backend separately from the project root:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

The client keeps the bearer token in `sessionStorage` for the current browser
tab session. This is more limited than persistent browser storage, but it is
still accessible to same-origin JavaScript and is not equivalent to an
HttpOnly cookie. Do not serve the app over plain HTTP outside local development.
