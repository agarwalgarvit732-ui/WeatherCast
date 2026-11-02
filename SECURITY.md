# 🛡️ WeatherCast - Security & Vulnerability Assessment Report

This document outlines the security architecture and vulnerability mitigations implemented in the **WeatherCast Weather Forecast Application**.

---

## 1. Vulnerability Mitigation Matrix

| CWE / OWASP Risk | Category | Vulnerability Description | Mitigation Strategy in WeatherCast |
| :--- | :--- | :--- | :--- |
| **CWE-798** | Hardcoded Credentials | Storing sensitive API keys in client-side HTML or JS, allowing key theft and quota exhaustion. | **Default Keyless Architecture**: Utilizes Open-Meteo's open weather and geocoding engine which requires **zero API keys**. Optional custom keys are stored in `localStorage` on the client only and never committed. |
| **CWE-79** | Cross-Site Scripting (XSS) | Injecting malicious JavaScript via city search inputs, error messages, or manipulated API responses. | **Zero dynamic `innerHTML` sinks**: All text rendering strictly utilizes native `textContent` properties and secure DOM node creation (`document.createElement`). |
| **CWE-1021 / CWE-79** | Content Security Policy | Unauthorized scripts or data exfiltration from untrusted domains. | **Strict CSP Meta Header**: Scripts restricted to `'self'` (no inline script execution permitted). Network connections limited to authorized weather endpoints. |
| **CWE-20** | Improper Input Validation | Dangerous special characters, SQL/command injection payloads, or buffer bloat in search parameters. | **Strict Sanitization Pipeline**: Maximum input length bounded to 80 characters, control characters stripped, and all queries encoded via `encodeURIComponent()`. Coordinates validated via bounds checking (`-90 <= lat <= 90`, `-180 <= lon <= 180`). |
| **CWE-400** | Denial of Service / Flooding | Hanging requests, rapid API hammering, or unbounded memory consumption. | **Request Throttling & AbortController**: Each network request is bounded by an 8-second timeout. Consecutive searches debounce and cancel previous in-flight requests. Buttons are disabled during pending states. |
| **CWE-209** | Information Disclosure | Dumping raw exception stack traces or backend debug information to users. | **User-Facing Sanitized Alerts**: Catches all network and parsing exceptions and presents user-friendly explanations (e.g. "Location not found", "Network connection lost"). |
| **CWE-284** | Improper Access Control / Storage Failure | Application crashing in incognito mode or due to corrupted `localStorage`. | **Safe Storage Abstraction**: All storage interactions (`getItem`, `setItem`, `removeItem`) are wrapped in `try/catch` handlers with schema verification and default fallbacks. |
| **CWE-1022** | Reverse Tabnabbing | Outbound links hijacking window opener context. | External links and references enforce `rel="noopener noreferrer"`. |

---

## 2. Content Security Policy (CSP) Directives

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data: https:;
  connect-src 'self' https://geocoding-api.open-meteo.com https://api.open-meteo.com https://api.bigdatacloud.net https://api.openweathermap.org;
  object-src 'none';
  base-uri 'self';
  form-action 'self';
```

### Key Security Benefits of this Policy:
1. `script-src 'self'`: Disallows inline script tags and script injection. Even if an attacker somehow injected `<script>evil()</script>`, the browser blocks execution immediately.
2. `connect-src`: Prevents data exfiltration by locking network requests exclusively to authorized weather service domains.
3. `object-src 'none'`: Blocks Flash, Java applets, and other legacy plugin vulnerabilities.
4. `base-uri 'self'`: Prevents `<base>` tag injection attacks.

---

## 3. Defense-in-Depth Implementation Details

### A. Secret Management (Zero API Key Leakage)
In standard tutorial applications, developers often paste their personal OpenWeatherMap API key into frontend JavaScript files:
```javascript
// ❌ VULNERABLE:
const APIKey = "ad73d3b4bdac46033eefcd976849a972";
```
In this application:
1. The default provider is **Open-Meteo**, a publicly funded open API designed for high-resolution weather forecasts requiring **no authorization tokens**.
2. If the user chooses to supply their own OpenWeatherMap key, it is provided via an interactive Settings Dialog, retained in client-side storage, and never logged or exposed.

### B. Safe DOM Manipulation
To ensure complete immunity from DOM-based XSS:
```javascript
// ❌ VULNERABLE:
cityElement.innerHTML = `<h1>${userQuery}</h1>`;

//  SECURE (Used in WeatherCast):
const h1 = document.createElement('h1');
h1.textContent = userQuery; // Browser treats userQuery strictly as text, neutralizing HTML/scripts
cityElement.appendChild(h1);
```

### C. Input Sanitization
```javascript
function sanitizeCity(input) {
  if (typeof input !== 'string') return '';
  let clean = input.trim().replace(/[\x00-\x1F\x7F]/g, '');
  if (clean.length > 80) clean = clean.substring(0, 80);
  clean = clean.replace(/[<>"'`/\\{}[\]^~|+=*$%#@!&?;:]/g, '');
  return clean.trim();
}
```

---

## 4. Verification & Testing

To verify the application integrity:
1. Open `index.html` in any modern web browser.
2. Open DevTools Console (`F12`):
   - Confirm zero CSP violation warnings.
   - Confirm zero unhandled promise rejections.
3. Attempt XSS payloads in the search box:
   - `<script>alert(1)</script>` -> Sanitized and neutralized; rejected as invalid city or safely encoded.
4. Test offline resilience:
   - Toggle "Offline" in DevTools Network tab.
   - Notice the persistent offline notification and seamless presentation of cached forecast data.
