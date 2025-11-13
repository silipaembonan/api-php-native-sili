<?php
namespace Src\Config;
use PDO;
use PDOException;

class Database {
    private static ?PDO $pdo = null;

    public static function conn(array $cfg): PDO {
        if (!self::$pdo) {
            try {
                self::$pdo = new PDO(
                    $cfg['db']['dsn'],
                    $cfg['db']['user'],
                    $cfg['db']['pass'],
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    ]
                );
            } catch (PDOException $e) {
                die('Database connection failed: ' . $e->getMessage());
            }
        }
        return self::$pdo;
    }
}