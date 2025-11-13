<?php
$api_contract = [
    [
        "endpoint" => "/api/v1/health",
        "method" => "GET",
        "description" => "Memeriksa status kesehatan server (health check)",
        "request_body" => [],
        "response" => [
            "status" => "success",
            "message" => "Server is healthy"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/version",
        "method" => "GET",
        "description" => "Menampilkan versi API yang sedang digunakan",
        "request_body" => [],
        "response" => [
            "status" => "success",
            "version" => "v1.0.0"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/auth/login",
        "method" => "POST",
        "description" => "Autentikasi user menggunakan email dan password",
        "request_body" => [
            "email" => "string (required)",
            "password" => "string (required)"
        ],
        "response" => [
            "status" => "success",
            "token" => "string (JWT Token)"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/users",
        "method" => "GET",
        "description" => "Menampilkan daftar semua user",
        "request_body" => [],
        "response" => [
            "status" => "success",
            "data" => "array of user objects"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/users/{id}",
        "method" => "GET",
        "description" => "Menampilkan detail data user berdasarkan ID",
        "request_body" => [],
        "response" => [
            "status" => "success",
            "data" => "object user"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/users",
        "method" => "POST",
        "description" => "Menambahkan user baru ke dalam sistem",
        "request_body" => [
            "name" => "string (required)",
            "email" => "string (required)",
            "password" => "string (required)"
        ],
        "response" => [
            "status" => "success",
            "message" => "User created successfully",
            "data" => "object user"
        ],
        "status_code" => 201,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/users/{id}",
        "method" => "PUT",
        "description" => "Memperbarui data user berdasarkan ID",
        "request_body" => [
            "name" => "string (optional)",
            "email" => "string (optional)",
            "password" => "string (optional)"
        ],
        "response" => [
            "status" => "success",
            "message" => "User updated successfully",
            "data" => "object user"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/users/{id}",
        "method" => "DELETE",
        "description" => "Menghapus user berdasarkan ID",
        "request_body" => [],
        "response" => [
            "status" => "success",
            "message" => "User deleted successfully"
        ],
        "status_code" => 200,
        "version" => "v1"
    ],
    [
        "endpoint" => "/api/v1/upload",
        "method" => "POST",
        "description" => "Mengunggah file ke server",
        "request_body" => [
            "file" => "file (required)"
        ],
        "response" => [
            "status" => "success",
            "message" => "File uploaded successfully",
            "file_url" => "string (URL)"
        ],
        "status_code" => 200,
        "version" => "v1"
    ]
];

header('Content-Type: application/json');
echo json_encode($api_contract, JSON_PRETTY_PRINT);
?>