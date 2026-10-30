<?php
// ====== EDIT THESE 5 VALUES ======
const DB_HOST = 'localhost';
const DB_NAME = 'your_cpanel_database_name';   // e.g. cpuser_lostfound
const DB_USER = 'your_cpanel_database_user';   // e.g. cpuser_lfuser
const DB_PASS = 'your_database_password';
const ANTHROPIC_API_KEY = 'sk-ant-xxxxxxxxxxxxxxxx';

// ====== SIGN-IN PASSWORDS (required) ======
// Staff can mark items claimed. Admin can also delete reports and see the sign-in log.
// Pick long, different passwords. You may also paste a bcrypt hash ($2y$...) instead of plain text.
const STAFF_PASSWORD = 'staffpassword';
const ADMIN_PASSWORD = 'adminpassword';
// =================================

// Sign-in protection
const MAX_LOGIN_FAILS = 5;          // wrong passwords allowed before lockout
const LOCKOUT_MINUTES = 15;         // how long a visitor is locked out
const SESSION_HOURS = 8;            // how long a sign-in lasts
const REPORT_LIMIT_PER_HOUR = 10;   // new reports per visitor per hour (anti-spam)

// Models for the Quick / Balanced / Deep choices in the app
const MODEL_QUICK   = 'claude-haiku-5-5';
const MODEL_DEFAULT = 'claude-sonnet-5-5';
const MODEL_COMPLEX = 'claude-opus-5-5';

// Max AI requests per visitor per hour (protects your API key)
const AI_LIMIT_PER_HOUR = 40;

function db(): PDO {
  static $pdo = null;
  if ($pdo) return $pdo;
  $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
  $pdo->exec("CREATE TABLE IF NOT EXISTS items (
    id VARCHAR(64) PRIMARY KEY,
    data LONGTEXT NOT NULL,
    created_at BIGINT NOT NULL
  ) CHARACTER SET utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS ai_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(64), t INT, INDEX(ip,t)
  )");
  $pdo->exec("CREATE TABLE IF NOT EXISTS login_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(64), role VARCHAR(10), ok TINYINT NOT NULL DEFAULT 0, t INT,
    INDEX(ip,ok,t), INDEX(role,ok,t)
  )");
  $pdo->exec("CREATE TABLE IF NOT EXISTS report_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(64), t INT, INDEX(ip,t)
  )");
  return $pdo;
}

function cfg(string $k, $default) { return defined($k) ? constant($k) : $default; }
function client_ip(): string { return substr($_SERVER['REMOTE_ADDR'] ?? '0', 0, 64); }

// ---- Sessions / roles ----
function start_session(): void {
  if (session_status() === PHP_SESSION_ACTIVE) return;
  $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
  session_name('lfsid');
  session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Strict']);
  session_start();
}
function role_level(string $r): int { return $r === 'Admin' ? 2 : ($r === 'Staff' ? 1 : 0); }
function current_role(): string {
  start_session();
  if (!empty($_SESSION['role']) && !empty($_SESSION['exp']) && $_SESSION['exp'] > time()) return $_SESSION['role'];
  unset($_SESSION['role'], $_SESSION['exp']);
  return 'Student';
}
function require_role(string $min): void {
  $cur = current_role();
  if (role_level($cur) >= role_level($min)) return;
  json_out(['error' => $cur === 'Student' ? 'login_required' : 'forbidden'], $cur === 'Student' ? 401 : 403);
}
// Returns true/false, or null when no real password has been set in config.php
function check_password(string $role, string $input): ?bool {
  $stored = $role === 'Admin' ? cfg('ADMIN_PASSWORD', '') : cfg('STAFF_PASSWORD', '');
  if ($stored === '' || strpos($stored, 'change-this') === 0) return null;
  if (strncmp($stored, '$2y$', 4) === 0 || strncmp($stored, '$argon', 6) === 0) return password_verify($input, $stored);
  return hash_equals($stored, $input);
}

function json_out($data, int $code = 200): void {
  http_response_code($code);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}
