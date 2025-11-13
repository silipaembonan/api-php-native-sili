<?php
header('Content-Type: application/json');
$secret = 'sili_paembonan_luwu_selatan_secret_1';
function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function base64UrlDecode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $data .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}
$jwt = $_GET['token'] ?? '';
if (!$jwt) {
    $header = ['typ' => 'JWT', 'alg' => 'HS256'];
    $payload = [
        'sub' => 2,
        'name' => 'admin',
        'role' => 'admin',
        'iat' => time(),
        'exp' => time() + 3600
    ];
    $header64 = base64UrlEncode(json_encode($header));
    $payload64 = base64UrlEncode(json_encode($payload));
    $signature = base64UrlEncode(hash_hmac('sha256', "$header64.$payload64", $secret, true));
    $jwt = "$header64.$payload64.$signature";
    echo json_encode([
        'status' => 'success',
        'message' => 'New token generated (valid for 60 minutes)',
        'token' => $jwt
    ]);
    exit;
}
$parts = explode('.', $jwt);
if (count($parts) !== 3) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid token format']);
    exit;
}
list($header64, $payload64, $signature) = $parts;
$valid_signature = base64UrlEncode(hash_hmac('sha256', "$header64.$payload64", $secret, true));
if ($signature !== $valid_signature) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid token signature']);
    exit;
}
$payload = json_decode(base64UrlDecode($payload64), true);
if ($payload['exp'] < time()) {
    echo json_encode(['status' => 'error', 'message' => 'Token has expired']);
    exit;
}
echo json_encode([
    'status' => 'success',
    'message' => 'Token is valid',
    'data' => $payload
]);