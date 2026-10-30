<?php
require __DIR__.'/config.php';
try {
  $pdo = db();
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0';
  $pdo->prepare("DELETE FROM ai_log WHERE t < ?")->execute([time() - 3600]);
  $st = $pdo->prepare("SELECT COUNT(*) c FROM ai_log WHERE ip=?"); $st->execute([$ip]);
  if ((int)$st->fetch()['c'] >= AI_LIMIT_PER_HOUR) json_out(['error' => 'rate_limited'], 429);
  $pdo->prepare("INSERT INTO ai_log (ip,t) VALUES (?,?)")->execute([$ip, time()]);

  $b = json_decode(file_get_contents('php://input'), true) ?: [];
  $prompt = (string)($b['prompt'] ?? '');
  if ($prompt === '' || strlen($prompt) > 60000) json_out(['error' => 'bad prompt'], 400);
  $tier = $b['tier'] ?? 'default';
  $model = $tier === 'quick' ? MODEL_QUICK : ($tier === 'complex' ? MODEL_COMPLEX : MODEL_DEFAULT);

  $content = [];
  if (!empty($b['image']) && preg_match('#^data:(image/(?:jpeg|png|webp|gif));base64,(.+)$#s', $b['image'], $m)) {
    $content[] = ['type' => 'image', 'source' => ['type' => 'base64', 'media_type' => $m[1], 'data' => $m[2]]];
  }
  $content[] = ['type' => 'text', 'text' => $prompt];

  $ch = curl_init('https://api.anthropic.com/v1/messages');
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 60,
    CURLOPT_HTTPHEADER => ['content-type: application/json', 'x-api-key: '.ANTHROPIC_API_KEY, 'anthropic-version: 2023-06-01'],
    CURLOPT_POSTFIELDS => json_encode(['model' => $model, 'max_tokens' => 1000, 'messages' => [['role' => 'user', 'content' => $content]]]),
  ]);
  $res = curl_exec($ch);
  $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  if ($res === false) json_out(['error' => 'curl: '.curl_error($ch)], 502);
  $j = json_decode($res, true);
  if ($http !== 200) json_out(['error' => $j['error']['message'] ?? 'AI error', 'status' => $http], 502);
  $text = '';
  foreach ($j['content'] ?? [] as $blk) if (($blk['type'] ?? '') === 'text') $text .= $blk['text'];
  json_out(['text' => $text]);
} catch (Throwable $e) {
  json_out(['error' => 'server error', 'detail' => $e->getMessage()], 500);
}
