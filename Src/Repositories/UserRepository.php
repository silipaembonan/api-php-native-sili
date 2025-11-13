<?php
namespace Src\Repositories;

use PDO;
use Src\Config\Database;

class UserRepository {
    private PDO $db;

    public function __construct(array $cfg) {
        $this->db = Database::conn($cfg);
    }

    public function paginate($page, $per) {
        $off = ($page - 1) * $per;
        $total = (int) $this->db->query('SELECT COUNT(*) FROM users')->fetchColumn();

        $stmt = $this->db->prepare('SELECT id, name, email, role, created_at, updated_at 
            FROM users ORDER BY id DESC LIMIT :per OFFSET :off');
        $stmt->bindValue(':per', (int)$per, PDO::PARAM_INT);
        $stmt->bindValue(':off', (int)$off, PDO::PARAM_INT);
        $stmt->execute();

        return [
            'data' => $stmt->fetchAll(PDO::FETCH_ASSOC),
            'meta' => [
                'total' => $total,
                'page' => $page,
                'per_page' => $per,
                'last_page' => max(1, (int)ceil($total / $per))
            ]
        ];
    }

    public function find($id) {
        $s = $this->db->prepare('SELECT id, name, email, role, created_at, updated_at FROM users WHERE id=?');
        $s->execute([$id]);
        return $s->fetch(PDO::FETCH_ASSOC);
    }

    public function create($name, $email, $hash, $role = 'user') {
        $this->db->beginTransaction();
        try {
            $s = $this->db->prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)');
            $s->execute([$name, $email, $hash, $role]);
            $id = (int)$this->db->lastInsertId();
            $this->db->commit();
            return $this->find($id);
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    public function update($id, $name, $email, $role) {
        $s = $this->db->prepare('UPDATE users SET name=?, email=?, role=? WHERE id=?');
        $s->execute([$name, $email, $role, $id]);
        return $this->find($id);
    }

    public function delete($id) {
        $s = $this->db->prepare('DELETE FROM users WHERE id=?');
        return $s->execute([$id]);
    }
}
