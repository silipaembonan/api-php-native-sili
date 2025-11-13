<?php
namespace Src\Helpers;
class Jwt
{
    public static function base64url($s)
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }
    public static function sign(array $payload, string $secret, string $alg = 'HS256')
    {
        $header = ['typ' => 'JWT', 'alg' => $alg];
        $seg = [];
        $seg[] = self::base64url(json_encode($header));
        $seg[] = self::base64url(json_encode($payload));
        $sig = hash_hmac('sha256', implode('.', $seg), $secret, true);
        $seg[] = self::base64url($sig);
        return implode('.', $seg);
    }
    public static function verify(string $jwt, string $secret)
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        [$sh, $sp, $ss] = $parts;
        $sig = self::base64url(hash_hmac('sha256', "$sh.$sp", $secret, true));
        if (!hash_equals($ss, $sig)) {
            return null;
        }
        $payload = json_decode(base64_decode(strtr($sp, '-_', '+/')), true);
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return null;
        }
        return $payload;
    }
}