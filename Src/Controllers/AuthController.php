<?php
namespace Src\Controllers;
use Src\Config\Database;
use Src\Helpers\Jwt;
use PDO;
class AuthController extends BaseController
{
    public function login()
    {
        $in = json_decode(file_get_contents('php://input'), true) ?? [];

        if (empty($in['email']) || empty($in['password'])) {
            return $this->error(422, 'Email & password required');
        }
        $db = Database::conn($this->cfg);
        $stmt = $db->prepare('
            SELECT 
                id, name, email, password_hash, role 
            FROM 
                users 
            WHERE 
                email = ?');
        $stmt->execute([$in['email']]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($in['password'], $user['password_hash'])) {
            return $this->error(401, 'Invalid credentials');
        }
        $payload = [
            'sub'   => $user['id'], 
            'name'  => $user['name'], 
            'role'  => $user['role'], 
            'iat'   => time(),
            'exp'   => time() + (3600)
        ];
        $token = Jwt::sign($payload, $this->cfg['app']['jwt_secret']);
        return Response::json(['token' => $token]);
    }
}