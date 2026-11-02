# ⛅ WeatherCast - Secure Weather Forecast Application

A modern, responsive, and privacy-focused Weather Forecast web application built with **Zero Vulnerabilities** following OWASP and CWE secure coding standards.

---

## 🌟 Key Features

- **Real-Time Weather**: Current temperature, feels-like temperature, weather condition description, today's high/low range, and dynamic weather icons.
- **Hourly Forecast (Next 24 Hours)**: Horizontal scroll strip displaying hour-by-hour temperature, rain probability, and weather conditions.
- **7-Day Weather Forecast**: Comprehensive daily outlook with condition descriptions, rain probability, and daily high/low temperatures.
- **Detailed Atmospheric Highlights**:
  - Humidity percentage (`humidity.png`)
  - Wind speed (km/h or mph) with 16-point cardinal compass direction (`wind.png`)
  - UV Index with color-coded safety level badges (Low, Moderate, High, Very High, Extreme)
  - Precipitation probability and rain amount
  - Atmospheric barometric pressure (hPa)
- **One-Click Unit Toggle**: Instantly switch between Metric (`°C`, `km/h`) and Imperial (`°F`, `mph`) units with instant DOM recalculation (no extra network requests).
- **GPS / Geolocation**: "📍 GPS" button with explicit user consent, permission error handling, and reverse geocoding.
- **Instant City Search & Quick Chips**:
  - Search any city worldwide with autocomplete/Enter key support.
  - Quick chips for popular cities: Mumbai, Delhi, London, New York, Tokyo, Paris, Sydney.
- **Offline & Cache Resilience**:
  - Seamlessly caches the last retrieved forecast in browser `localStorage`.
  - Automatically detects offline status (`navigator.onLine`) and displays cached data with an accessible notification.

---

## 🛡️ Security & Vulnerability Protections

This application eliminates the top vulnerabilities prevalent in web weather applications:

| Vulnerability | Mitigation |
| :--- | :--- |
| **CWE-798: Leaked / Hardcoded API Keys** | Uses **Open-Meteo** by default, requiring **zero API keys**. No secrets are exposed or committed. Users can optionally configure their own OpenWeatherMap key in settings (persisted solely in device `localStorage`). |
| **CWE-79: Cross-Site Scripting (XSS)** | **Zero dynamic `innerHTML` sinks**. All user inputs and API responses are inserted via `textContent` and native DOM nodes. |
| **CWE-1021 / CSP: Injection Attacks** | Strict **Content Security Policy** (`script-src 'self'`, `connect-src` limited only to authorized weather endpoints, `object-src 'none'`). |
| **CWE-20: Input Injection & Buffer Bloat** | Input sanitization, length bounding (max 80 chars), and strict `encodeURIComponent()` encoding for all query parameters. Latitude and longitude bounded via `Number.isFinite()`. |
| **CWE-400: Denial of Service / Hanging Requests** | 8-second `AbortController` timeouts prevent frozen sockets. Request-in-flight throttling prevents spamming. |
| **CWE-209: Sensitive Information Disclosure** | Raw backend error traces are suppressed; user-friendly alerts are displayed. |
| **CWE-284: Storage Exception Handling** | `localStorage` access wrapped in `try/catch` with fallback for restricted/incognito environments. |

For detailed security specifications, see [SECURITY.md](file:///c:/Users/agarw/OneDrive/Documents/All%20Websites/Weather%20App/SECURITY.md).

---

## 🚀 How to Run

Simply open [`index.html`](file:///c:/Users/agarw/OneDrive/Documents/All%20Websites/Weather%20App/index.html) in any modern web browser:
- Double-click `index.html` in your file explorer, OR
- Serve with any static web server (e.g. `npx serve .` or Python `python -m http.server 8000`).

To run the automated security and unit tests:
```bash
node test.js
```
