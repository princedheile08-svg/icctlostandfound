<?php
require __DIR__.'/config.php';
try {
  $pdo = db();
  $action = $_GET['action'] ?? '';
  $ip = client_ip();

  // Block cross-site form posts: real requests from the page are JSON
  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === false) {
    json_out(['error' => 'bad content type'], 415);
  }

  // ---- Public: list reports ----
  if ($action === 'list') {
    $rows = $pdo->query("SELECT id,data FROM items ORDER BY created_at DESC")->fetchAll();
    $out = [];
    foreach ($rows as $r) { $d = json_decode($r['data'], true); if (is_array($d)) { $d['id'] = $r['id']; $out[] = $d; } }
    json_out(['items' => $out]);
  }

  // ---- Who am I? ----
  if ($action === 'me') json_out(['role' => current_role()]);

  $body = json_decode(file_get_contents('php://input'), true) ?: [];

  // ---- Sign in (with lockout) ----
  if ($action === 'login') {
    $role = $body['role'] ?? '';
    $pw = (string)($body['password'] ?? '');
    if (!in_array($role, ['Staff', 'Admin'], true)) json_out(['error' => 'bad role'], 400);
    $max = max(1, (int)cfg('MAX_LOGIN_FAILS', 5));
    $win = max(1, (int)cfg('LOCKOUT_MINUTES', 15)) * 60;
    $now = time();
    $pdo->prepare("DELETE FROM login_log WHERE t < ?")->execute([$now - 30 * 86400]);

    // Count wrong passwords from this visitor since their last good sign-in
    $st = $pdo->prepare("SELECT COALESCE(MAX(t),0) m FROM login_log WHERE ip=? AND ok=1"); $st->execute([$ip]);
    $since = max($now - $win, (int)$st->fetch()['m']);
    $st = $pdo->prepare("SELECT COUNT(*) c, COALESCE(MAX(t),0) m FROM login_log WHERE ip=? AND ok=0 AND t>?"); $st->execute([$ip, $since]);
    $r = $st->fetch();
    if ((int)$r['c'] >= $max) json_out(['error' => 'locked', 'retry_after' => max(1, (int)$r['m'] + $win - $now)], 429);

    // Safety net against many different visitors guessing the same account
    $st = $pdo->prepare("SELECT COUNT(*) c, COALESCE(MAX(t),0) m FROM login_log WHERE role=? AND ok=0 AND t>?"); $st->execute([$role, $now - $win]);
    $g = $st->fetch();
    if ((int)$g['c'] >= $max * 10) json_out(['error' => 'locked', 'retry_after' => max(1, (int)$g['m'] + $win - $now)], 429);

    $ok = check_password($role, $pw);
    if ($ok === null) json_out(['error' => 'not_configured'], 503);

    if ($ok) {
      $pdo->prepare("INSERT INTO login_log (ip,role,ok,t) VALUES (?,?,1,?)")->execute([$ip, $role, $now]);
      start_session();
      session_regenerate_id(true);
      $_SESSION['role'] = $role;
      $_SESSION['exp'] = $now + max(1, (int)cfg('SESSION_HOURS', 8)) * 3600;
      json_out(['ok' => true, 'role' => $role]);
    }

    usleep(600000); // slow down guessing
    $pdo->prepare("INSERT INTO login_log (ip,role,ok,t) VALUES (?,?,0,?)")->execute([$ip, $role, $now]);
    $left = $max - ((int)$r['c'] + 1);
    if ($left <= 0) json_out(['error' => 'locked', 'retry_after' => $win], 429);
    json_out(['error' => 'bad_password', 'remaining' => $left, 'lock_minutes' => (int)($win / 60)], 401);
  }

  if ($action === 'logout') {
    start_session();
    $_SESSION = [];
    session_destroy();
    json_out(['ok' => true]);
  }

  // ---- Admin: recent sign-in attempts ----
  if ($action === 'loginlog') {
    require_role('Admin');
    $rows = $pdo->query("SELECT role,ok,ip,t FROM login_log ORDER BY id DESC LIMIT 15")->fetchAll();
    json_out(['log' => $rows]);
  }

  // ---- Save a report ----
  if ($action === 'save') {
    $it = $body['item'] ?? null;
    if (!is_array($it) || empty($it['id']) || !is_string($it['id']) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $it['id'])) json_out(['error' => 'bad item'], 400);
    $id = $it['id']; unset($it['id']);
    $json = json_encode($it, JSON_UNESCAPED_UNICODE);
    if (strlen($json) > 1500000) json_out(['error' => 'item too large'], 413);

    $st = $pdo->prepare("SELECT 1 FROM items WHERE id=?"); $st->execute([$id]);
    if ($st->fetch()) {
      require_role('Staff');                     // editing / claiming needs Staff or Admin
    } elseif (role_level(current_role()) < 1) {  // brand-new report from a student
      if (!in_array($it['status'] ?? '', ['Lost', 'Found'], true) || !in_array($it['type'] ?? '', ['Lost', 'Found'], true)) json_out(['error' => 'forbidden'], 403);
      $lim = max(1, (int)cfg('REPORT_LIMIT_PER_HOUR', 10));
      $pdo->prepare("DELETE FROM report_log WHERE t < ?")->execute([time() - 3600]);
      $st = $pdo->prepare("SELECT COUNT(*) c FROM report_log WHERE ip=?"); $st->execute([$ip]);
      if ((int)$st->fetch()['c'] >= $lim) json_out(['error' => 'rate_limited'], 429);
      $pdo->prepare("INSERT INTO report_log (ip,t) VALUES (?,?)")->execute([$ip, time()]);
    }
    $created = (int)($it['createdAt'] ?? round(microtime(true) * 1000));
    $st = $pdo->prepare("INSERT INTO items (id,data,created_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data)");
    $st->execute([$id, $json, $created]);
    json_out(['ok' => true]);
  }

  // ---- Delete (Admin only) ----
  if ($action === 'delete') {
    require_role('Admin');
    $id = (string)($body['id'] ?? '');
    $pdo->prepare("DELETE FROM items WHERE id=?")->execute([$id]);
    json_out(['ok' => true]);
  }

  json_out(['error' => 'unknown action'], 400);
} catch (Throwable $e) {
  json_out(['error' => 'server error', 'detail' => $e->getMessage()], 500);
}
