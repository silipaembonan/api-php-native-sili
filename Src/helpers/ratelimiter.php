<?php
namespace Src\Helpers;class RateLimiter{
    public static function check($key, $max = 60, $window = 60) {
        $file = __DIR__ . '/../../logs/ratelimit_' . md5($key) . '.txt';
        $now = time();
        $hits = [];
        if (file_exists($file)) {
            $content = file_get_contents($file);
            if ($content) {
                $lines = explode("\n", trim($content));
                foreach ($lines as $line) {
                    $timestamp = (int) $line;
                    if ($timestamp > $now - $window) {
                        $hits[] = $timestamp;
                    }
                }
            }
        }
        if (count($hits) >= $max) {
            return false;
        }
        $hits[] = $now;
        file_put_contents($file, implode("\n", $hits));
        return true;
    }
}