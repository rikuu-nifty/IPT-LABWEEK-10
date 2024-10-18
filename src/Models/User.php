<?php

namespace App\Models;

use App\Models\BaseModel;
use \PDO;

class User extends BaseModel
{
    public function save($username, $email, $first_name, $last_name, $password) {
        $sql = "INSERT INTO users (username, email, first_name, last_name, password_hash) 
                VALUES (:username, :email, :first_name, :last_name, :password)";
        
        $statement = $this->db->prepare($sql);
        
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        // Bind parameters
        $statement->bindParam(':username', $username);
        $statement->bindParam(':email', $email);
        $statement->bindParam(':first_name', $first_name);
        $statement->bindParam(':last_name', $last_name);
        $statement->bindParam(':password', $hashed_password);
        
        // Execute the statement
        $statement->execute();
    
        // No need to fetch results for an INSERT statement
        return $statement->rowCount(); // Return the number of affected rows

        
    }

    // Function to retrieve password hash for login verification
    public function getPassword($username) {
        $sql = "SELECT password_hash FROM users WHERE username = :username;";
        $statement = $this->db->prepare($sql);

        $statement->execute(['username' => $username]);
        $result = $statement->fetch(PDO::FETCH_ASSOC);
        return $result['password_hash'] ?? null;
    }
    
    public function getData() {
        $sql = "SELECT * FROM users;";
        $statement = $this->db->prepare($sql);

        $statement->execute();
        return $statement->fetchAll(PDO::FETCH_CLASS, '\App\Models\User');
    }
    public function getAllUsers()
    {
        $query = "SELECT id, first_name, last_name, email FROM users"; // Adjust according to your table structure
        $stmt = $this->db->prepare($query);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC); // Return data as an associative array
    }
}   