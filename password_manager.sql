CREATE DATABASE password_manager_db;


CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  masterKey TEXT NOT NULL
);

