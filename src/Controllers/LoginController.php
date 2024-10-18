<?php

namespace App\Controllers;

use App\Models\User;

class LoginController extends BaseController
{

    private function startSession() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    }
    
    public function index()
    {
        $this->startSession(); // Start session if not already started

        // Pass initial form data: form enabled and no remaining_attempts
        $data = [
            'remaining_attempts' => null,
            'form_disabled' => false
        ];

        $template = 'login-form';
        return $this->render($template, $data);
    }

    public function login()
    {
        $this->startSession(); // Start session if not started

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'] ?? null; // Ensure the name is 'username'
            $password = $_POST['password'] ?? null;

            if (empty($username) || empty($password)) {
                $errors[] = "Username and password are required.";
                return $this->LoginFormErrorAttempt($errors, null, false);               
            }

            // Initialize User model and fetch password hash
            $user = new User();
            $saved_password_hash = $user->getPassword($username);

            if ($saved_password_hash && password_verify($password, $saved_password_hash)) {
                // Reset login attempts on successful login
                $_SESSION['login_attempts'] = 0;

                // Store session data
                $_SESSION['is_logged_in'] = true;
                $_SESSION['username'] = $username;

                // Redirect to welcome page
                header("Location: /welcome");
                exit;

            } else {
                // Increment failed login attempts
                $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;

                // Get remaining attempts
                $max_attempts = 3;
                $remaining_attempts = $max_attempts - $_SESSION['login_attempts'];

                if ($_SESSION['login_attempts'] >= $max_attempts) {
                    $errors[] = "Too many failed login attempts. Please try again later.";
                    return $this->render('login-form', [
                        'errors' => $errors, 
                        'form_disabled' => true // Disable form after max attempts
                    ]);
                } else {
                    $errors[] = "Invalid username or password. Attempts remaining: $remaining_attempts.";
                    return $this->LoginFormErrorAttempt($errors, $remaining_attempts, false);
                }
            }
        } else {
            return $this->index(); // Redirect to login form if not POST
        }
    }

    private function LoginFormErrorAttempt($errors, $remainingAttempts = null, $formDisabled = false) {
        return $this->render('login-form', [
            'errors' => $errors,
            'form_disabled' => $formDisabled,
            'remaining_attempts' => $remainingAttempts // Pass remaining attempts if provided
        ]);
    }

    public function logout() {
        $this->startSession();
        session_destroy(); // Destroy session on logout
        header("Location: /");
        exit;
    }

}
