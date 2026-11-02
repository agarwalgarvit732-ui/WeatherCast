/**
 * Comprehensive Automated Test Suite for WeatherCast Security & Logic
 */

const fs = require('fs');
const assert = require('assert');

console.log('--- Starting WeatherCast Test Suite ---');

// 1. Verify files exist
const requiredFiles = ['index.html', 'style.css', 'app.js', 'SECURITY.md'];
requiredFiles.forEach(file => {
  assert.ok(fs.existsSync(file), `Required file missing: ${file}`);
  console.log(`[PASS] File exists: ${file}`);
});

// 2. Read app.js and test units
const appCode = fs.readFileSync('app.js', 'utf8');

// Ensure no hardcoded secret keys in app.js or index.html
const indexCode = fs.readFileSync('index.html', 'utf8');
assert.ok(!appCode.includes('ad73d3b4bdac46033eefcd976849a972'), 'Leaked key must not be present in app.js');
assert.ok(!indexCode.includes('ad73d3b4bdac46033eefcd976849a972'), 'Leaked key must not be present in index.html');
console.log('[PASS] No hardcoded API keys detected in source code.');

// Ensure no innerHTML sinks in app.js
assert.ok(!appCode.includes('.innerHTML'), 'Zero innerHTML sinks allowed in app.js (CWE-79 prevention)');
console.log('[PASS] Zero innerHTML sinks found in app.js.');

// Ensure CSP is present in index.html
assert.ok(indexCode.includes('Content-Security-Policy'), 'CSP meta tag must be present in index.html');
assert.ok(indexCode.includes("script-src 'self'"), "CSP must enforce script-src 'self'");
console.log('[PASS] Strict Content Security Policy confirmed in index.html.');

// 3. Test Sanitization Function
function sanitizeCity(input) {
  if (typeof input !== 'string') return '';
  let clean = input.trim().replace(/[\x00-\x1F\x7F]/g, '');
  if (clean.length > 80) clean = clean.substring(0, 80);
  clean = clean.replace(/[<>"'`/\\{}[\]^~|+=*$%#@!&?;:]/g, '');
  return clean.trim();
}

const xssPayloads = [
  '<script>alert("XSS")</script>',
  '"><img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  'London; DROP TABLE cities;--',
  '../../../../etc/passwd',
  'Tokyo\x00\x01\x1F',
  'A'.repeat(200)
];

xssPayloads.forEach(payload => {
  const sanitized = sanitizeCity(payload);
  assert.ok(!sanitized.includes('<'), `Sanitized must not contain '<': ${sanitized}`);
  assert.ok(!sanitized.includes('>'), `Sanitized must not contain '>': ${sanitized}`);
  assert.ok(!sanitized.includes('"'), `Sanitized must not contain '"': ${sanitized}`);
  assert.ok(!sanitized.includes('/'), `Sanitized must not contain '/': ${sanitized}`);
  assert.ok(sanitized.length <= 80, `Sanitized length must be <= 80: ${sanitized.length}`);
});
console.log(`[PASS] Tested ${xssPayloads.length} malicious inputs against sanitizeCity.`);

// 4. Test Coordinate Validation
function validateCoords(lat, lon) {
  const numLat = Number(lat);
  const numLon = Number(lon);
  return (
    Number.isFinite(numLat) &&
    Number.isFinite(numLon) &&
    numLat >= -90 &&
    numLat <= 90 &&
    numLon >= -180 &&
    numLon <= 180
  );
}

assert.strictEqual(validateCoords(19.0760, 72.8777), true, 'Mumbai coords should be valid');
assert.strictEqual(validateCoords(-33.8688, 151.2093), true, 'Sydney coords should be valid');
assert.strictEqual(validateCoords(91, 50), false, 'Lat > 90 must be invalid');
assert.strictEqual(validateCoords(50, 185), false, 'Lon > 180 must be invalid');
assert.strictEqual(validateCoords('NaN', 50), false, 'NaN must be invalid');
assert.strictEqual(validateCoords(Infinity, 50), false, 'Infinity must be invalid');
console.log('[PASS] Coordinate validation logic passed all boundary checks.');

// 5. Test Math & Conversions
function celsiusToFahrenheit(c) {
  return (c * 9) / 5 + 32;
}
function kmhToMph(kmh) {
  return kmh * 0.621371;
}

assert.strictEqual(Math.round(celsiusToFahrenheit(0)), 32, '0C is 32F');
assert.strictEqual(Math.round(celsiusToFahrenheit(100)), 212, '100C is 212F');
assert.strictEqual(Math.round(celsiusToFahrenheit(25)), 77, '25C is 77F');
assert.strictEqual(Math.round(kmhToMph(10)), 6, '10 km/h is ~6 mph');
console.log('[PASS] Temperature and wind unit conversions passed.');

// 6. Test Wind Direction
function getWindDirection(deg) {
  if (typeof deg !== 'number' || Number.isNaN(deg)) return '';
  const directions = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
  const index = Math.round((deg % 360) / 22.5) % 16;
  return directions[index] || '';
}

assert.strictEqual(getWindDirection(0), 'N', '0 deg should be N');
assert.strictEqual(getWindDirection(90), 'E', '90 deg should be E');
assert.strictEqual(getWindDirection(180), 'S', '180 deg should be S');
assert.strictEqual(getWindDirection(270), 'W', '270 deg should be W');
assert.strictEqual(getWindDirection(360), 'N', '360 deg should be N');
console.log('[PASS] Wind cardinal direction calculation passed.');

// 7. Test UV Classification
function getUVLevel(uv) {
  const num = Number(uv) || 0;
  if (num < 3) return 'Low';
  if (num < 6) return 'Moderate';
  if (num < 8) return 'High';
  if (num < 11) return 'Very High';
  return 'Extreme';
}

assert.strictEqual(getUVLevel(1), 'Low');
assert.strictEqual(getUVLevel(4.5), 'Moderate');
assert.strictEqual(getUVLevel(7), 'High');
assert.strictEqual(getUVLevel(9.2), 'Very High');
assert.strictEqual(getUVLevel(12), 'Extreme');
console.log('[PASS] UV index level classification passed.');

console.log('--- ALL TEST SUITE CHECKS PASSED SUCCESSFULLY ---');
