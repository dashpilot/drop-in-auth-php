<?php
/**
 * Drop-in Auth System - Single-File Application
 * Using Bramus Router, SQLite, and BladeOne
 */

// Enable error reporting for development
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Session start
session_start();

// Composer autoload - you'll need to run:
// composer require bramus/router eftec/bladeone
require_once 'vendor/autoload.php';

// Import necessary classes
use Bramus\Router\Router;
use eftec\bladeone\BladeOne;

/**
 * Database Class - SQLite Wrapper
 */
class Database {
    private static $instance = null;
    private $db;

    private function __construct() {
        $this->db = new SQLite3('auth_system.db');
        $this->createTables();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function createTables() {
        // Create users table if it doesn't exist
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');
        
        // Create login_attempts table for rate limiting
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                email TEXT,
                attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');
    }

    public function query($sql, $params = []) {
        $stmt = $this->db->prepare($sql);
        
        foreach ($params as $key => $value) {
            $stmt->bindValue(is_numeric($key) ? $key + 1 : $key, $value);
        }
        
        $result = $stmt->execute();
        return $result;
    }

    public function fetchAll($sql, $params = []) {
        $result = $this->query($sql, $params);
        $rows = [];
        
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        
        return $rows;
    }

    public function fetch($sql, $params = []) {
        $result = $this->query($sql, $params);
        return $result->fetchArray(SQLITE3_ASSOC);
    }

    public function lastInsertId() {
        return $this->db->lastInsertRowID();
    }
}

/**
 * Auth Class - Handles user authentication
 */
class Auth {
    private $db;
    private $maxAttempts = 5; // Maximum login attempts allowed
    private $timeWindow = 15; // Time window in minutes for rate limiting
    
    public function __construct() {
        $this->db = Database::getInstance();
    }
    
    /**
     * Get client IP address
     * 
     * @return string
     */
    private function getIpAddress() {
        // Check for proxy
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        }
        
        return $ip;
    }
    
    /**
     * Record a login attempt
     * 
     * @param string $email
     * @return void
     */
    private function recordLoginAttempt($email = null) {
        $ip = $this->getIpAddress();
        
        $this->db->query(
            "INSERT INTO login_attempts (ip_address, email) VALUES (:ip, :email)",
            [':ip' => $ip, ':email' => $email]
        );
    }
    
    /**
     * Check if user is rate limited
     * 
     * @param string $email
     * @return array
     */
    private function checkRateLimit($email = null) {
        $ip = $this->getIpAddress();
        $timeAgo = date('Y-m-d H:i:s', time() - ($this->timeWindow * 60));
        
        // Count attempts by IP and optionally by email
        $params = [':ip' => $ip, ':time_ago' => $timeAgo];
        $sql = "SELECT COUNT(*) as count FROM login_attempts 
                WHERE ip_address = :ip AND attempt_time > :time_ago";
        
        if ($email) {
            $sql .= " AND (email IS NULL OR email = :email)";
            $params[':email'] = $email;
        }
        
        $result = $this->db->fetch($sql, $params);
        $attempts = $result['count'];
        
        $remainingAttempts = $this->maxAttempts - $attempts;
        $isLimited = $remainingAttempts <= 0;
        
        return [
            'isLimited' => $isLimited,
            'remainingAttempts' => max(0, $remainingAttempts),
            'timeWindow' => $this->timeWindow
        ];
    }
    
    /**
     * Clean up old login attempts
     * 
     * @return void
     */
    private function cleanupOldAttempts() {
        // Delete attempts older than the time window
        $timeAgo = date('Y-m-d H:i:s', time() - ($this->timeWindow * 60));
        $this->db->query(
            "DELETE FROM login_attempts WHERE attempt_time < :time_ago",
            [':time_ago' => $timeAgo]
        );
    }
    
    public function register($username, $email, $password) {
        // Check rate limit for registration
        $rateLimit = $this->checkRateLimit();
        if ($rateLimit['isLimited']) {
            return [
                'success' => false,
                'message' => "Too many registration attempts. Please try again after {$this->timeWindow} minutes.",
                'rateLimit' => $rateLimit
            ];
        }
        
        // Check if user already exists
        $user = $this->db->fetch("SELECT * FROM users WHERE username = :username OR email = :email", [
            ':username' => $username,
            ':email' => $email
        ]);
        
        if ($user) {
            // Record failed attempt
            $this->recordLoginAttempt(null);
            
            return [
                'success' => false,
                'message' => 'Username or email already exists'
            ];
        }
        
        // Hash password
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        
        // Insert new user
        $this->db->query("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)", [
            ':username' => $username,
            ':email' => $email,
            ':password' => $passwordHash
        ]);
        
        // Cleanup old attempts
        $this->cleanupOldAttempts();
        
        return [
            'success' => true,
            'message' => 'Registration successful'
        ];
    }
    
    public function login($email, $password) {
        // Check rate limit
        $rateLimit = $this->checkRateLimit($email);
        if ($rateLimit['isLimited']) {
            return [
                'success' => false,
                'message' => "Too many failed login attempts. Please try again after {$this->timeWindow} minutes.",
                'rateLimit' => $rateLimit
            ];
        }
        
        $user = $this->db->fetch("SELECT * FROM users WHERE email = :email", [
            ':email' => $email
        ]);
        
        if (!$user) {
            // Record failed attempt
            $this->recordLoginAttempt($email);
            
            return [
                'success' => false,
                'message' => 'User not found',
                'remainingAttempts' => $rateLimit['remainingAttempts'] - 1
            ];
        }
        
        if (password_verify($password, $user['password'])) {
            // Successful login - set session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['logged_in'] = true;
            
            // Cleanup old attempts on successful login
            $this->cleanupOldAttempts();
            
            return [
                'success' => true,
                'message' => 'Login successful'
            ];
        }
        
        // Record failed attempt
        $this->recordLoginAttempt($email);
        
        return [
            'success' => false,
            'message' => 'Invalid password',
            'remainingAttempts' => $rateLimit['remainingAttempts'] - 1
        ];
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }
    
    public function logout() {
        session_unset();
        session_destroy();
        return true;
    }
    
    public function getCurrentUser() {
        if (!$this->isLoggedIn()) {
            return null;
        }
        
        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'email' => $_SESSION['email']
        ];
    }
}

/**
 * App Class - Main application logic
 */
class App {
    private $router;
    private $blade;
    private $auth;
    private $db;
    
    public function __construct() {
        // Create views directory if it doesn't exist
        if (!file_exists('views')) {
            mkdir('views', 0755, true);
            mkdir('views/cache', 0755, true);
            
            // Create initial views
            $this->createInitialViews();
        }
        
        // Setup BladeOne templating
        $this->blade = new BladeOne('views', 'views/cache', BladeOne::MODE_AUTO);
        
        // Get database and auth instances
        $this->db = Database::getInstance();
        $this->auth = new Auth();
        
        // Setup router
        $this->router = new Router();
        $this->setupRoutes();
    }
    
    private function createInitialViews() {
        // Layout view
        file_put_contents('views/layout.blade.php', $this->getLayoutTemplate());
        
        // Home view
        file_put_contents('views/home.blade.php', $this->getHomeTemplate());
        
        // Login view
        file_put_contents('views/login.blade.php', $this->getLoginTemplate());
        
        // Register view
        file_put_contents('views/register.blade.php', $this->getRegisterTemplate());
        
        // Dashboard view
        file_put_contents('views/dashboard.blade.php', $this->getDashboardTemplate());
    }
    
    private function setupRoutes() {
        // Add middleware for protected routes
        $this->router->before('GET|POST', '/dashboard', function() {
            if (!$this->auth->isLoggedIn()) {
                header('Location: /login');
                exit();
            }
        });
        
        // Define routes
        $this->router->get('/', [$this, 'homeHandler']);
        $this->router->get('/login', [$this, 'loginPageHandler']);
        $this->router->post('/login', [$this, 'loginHandler']);
        $this->router->get('/register', [$this, 'registerPageHandler']);
        $this->router->post('/register', [$this, 'registerHandler']);
        $this->router->get('/dashboard', [$this, 'dashboardHandler']);
        $this->router->get('/logout', [$this, 'logoutHandler']);
    }
    
    public function run() {
        $this->router->run();
    }
    
    // Route handlers
    public function homeHandler() {
        echo $this->blade->run('home', [
            'title' => 'Welcome to Auth System',
            'isLoggedIn' => $this->auth->isLoggedIn(),
            'user' => $this->auth->getCurrentUser()
        ]);
    }
    
    public function loginPageHandler() {
        if ($this->auth->isLoggedIn()) {
            header('Location: /dashboard');
            exit();
        }
        
        echo $this->blade->run('login', [
            'title' => 'Login',
            'error' => $_SESSION['login_error'] ?? null
        ]);
        
        // Clear any error message
        unset($_SESSION['login_error']);
    }
    
    public function loginHandler() {
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        
        $result = $this->auth->login($email, $password);
        
        if ($result['success']) {
            header('Location: /dashboard');
            exit();
        } else {
            // Add remaining attempts information to the error message if available
            if (isset($result['remainingAttempts'])) {
                $result['message'] .= $result['remainingAttempts'] > 0 
                    ? " (Remaining attempts: {$result['remainingAttempts']})" 
                    : "";
            }
            
            $_SESSION['login_error'] = $result['message'];
            header('Location: /login');
            exit();
        }
    }
    
    public function registerPageHandler() {
        if ($this->auth->isLoggedIn()) {
            header('Location: /dashboard');
            exit();
        }
        
        echo $this->blade->run('register', [
            'title' => 'Register',
            'error' => $_SESSION['register_error'] ?? null
        ]);
        
        // Clear any error message
        unset($_SESSION['register_error']);
    }
    
    public function registerHandler() {
        $username = $_POST['username'] ?? '';
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        // Basic validation
        if (empty($username) || empty($email) || empty($password)) {
            $_SESSION['register_error'] = 'All fields are required';
            header('Location: /register');
            exit();
        }
        
        if ($password !== $confirmPassword) {
            $_SESSION['register_error'] = 'Passwords do not match';
            header('Location: /register');
            exit();
        }
        
        $result = $this->auth->register($username, $email, $password);
        
        if ($result['success']) {
            // Auto login after registration
            $this->auth->login($email, $password);
            header('Location: /dashboard');
            exit();
        } else {
            // If rate limited, show appropriate message
            if (isset($result['rateLimit']) && $result['rateLimit']['isLimited']) {
                $_SESSION['register_error'] = $result['message'];
            } else {
                $_SESSION['register_error'] = $result['message'];
            }
            
            header('Location: /register');
            exit();
        }
    }
    
    public function dashboardHandler() {
        echo $this->blade->run('dashboard', [
            'title' => 'Dashboard',
            'user' => $this->auth->getCurrentUser()
        ]);
    }
    
    public function logoutHandler() {
        $this->auth->logout();
        header('Location: /');
        exit();
    }
    
    // Template getters
    private function getLayoutTemplate() {
        return <<<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $title }} - Auth System</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #6366f1;
            --primary-hover: #4f46e5;
            --dark-color: #1e293b;
            --light-color: #f8fafc;
            --gray-color: #64748b;
            --error-color: #ef4444;
            --success-color: #22c55e;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            line-height: 1.6;
            color: var(--dark-color);
            background-color: #f1f5f9;
            min-height: 100vh;
        }
        
        .container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        header {
            background-color: white;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1rem 0;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            font-weight: 700;
            font-size: 1.5rem;
            color: var(--dark-color);
            text-decoration: none;
        }
        
        .logo-icon {
            color: var(--primary-color);
            margin-right: 0.5rem;
        }
        
        nav ul {
            display: flex;
            list-style: none;
            align-items: center;
        }
        
        nav ul li {
            margin-left: 1.5rem;
        }
        
        nav ul li a {
            color: var(--gray-color);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        nav ul li a:hover {
            color: var(--primary-color);
        }
        
        .btn {
            display: inline-block;
            background-color: var(--primary-color);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            text-decoration: none;
            font-weight: 500;
            transition: background-color 0.3s;
            border: none;
            cursor: pointer;
            font-size: 1rem;
        }
        
        .btn:hover {
            background-color: var(--primary-hover);
            color: white;
        }
        
        .btn-outline {
            background-color: transparent;
            color: var(--primary-color);
            border: 1px solid var(--primary-color);
        }
        
        .btn-outline:hover {
            background-color: var(--primary-color);
            color: white;
        }
        
        main {
            padding: 2rem 0;
        }
        
        .card {
            background-color: white;
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #cbd5e1;
            border-radius: 0.375rem;
            font-family: 'Inter', sans-serif;
            font-size: 1rem;
        }
        
        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }
        
        .alert {
            padding: 1rem;
            border-radius: 0.375rem;
            margin-bottom: 1.5rem;
        }
        
        .alert-error {
            background-color: #fee2e2;
            color: var(--error-color);
            border: 1px solid #fecaca;
        }
        
        .alert-success {
            background-color: #dcfce7;
            color: var(--success-color);
            border: 1px solid #bbf7d0;
        }
        
        .section-title {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--dark-color);
        }
        
        .text-center {
            text-align: center;
        }
        
        .mt-4 {
            margin-top: 1rem;
        }
        
        footer {
            background-color: white;
            padding: 2rem 0;
            margin-top: 2rem;
            border-top: 1px solid #e2e8f0;
        }
        
        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .footer-copyright {
            color: var(--gray-color);
        }
        
        @media (max-width: 768px) {
            .header-content,
            .footer-content {
                flex-direction: column;
                text-align: center;
            }
            
            nav ul {
                margin-top: 1rem;
            }
            
            nav ul li {
                margin: 0 0.75rem;
            }
            
            .footer-content {
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="header-content">
                <a href="/" class="logo">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 448 512" width="18" height="18" style="fill: var(--dark-color); margin-right: 0.5rem;">
                        <path d="M144 144l0 48 160 0 0-48c0-44.2-35.8-80-80-80s-80 35.8-80 80zM80 192l0-48C80 64.5 144.5 0 224 0s144 64.5 144 144l0 48 16 0c35.3 0 64 28.7 64 64l0 192c0 35.3-28.7 64-64 64L64 512c-35.3 0-64-28.7-64-64L0 256c0-35.3 28.7-64 64-64l16 0z"/>
                    </svg>
                    Drop-in Auth
                </a>
                <nav>
                    <ul>
                        <li><a href="/">Home</a></li>
                        @if(isset($isLoggedIn) && $isLoggedIn)
                            <li><a href="/dashboard">Dashboard</a></li>
                            <li><a href="/logout" class="btn">Logout</a></li>
                        @else
                            <li><a href="/login">Login</a></li>
                            <li><a href="/register" class="btn">Register</a></li>
                        @endif
                    </ul>
                </nav>
            </div>
        </div>
    </header>
    
    <main>
        <div class="container">
            @yield('content')
        </div>
    </main>
    
    <footer>
        <div class="container">
            <div class="footer-content">
                <div class="footer-copyright">
                    &copy; {{ date('Y') }} Auth System. All rights reserved.
                </div>
            </div>
        </div>
    </footer>
</body>
</html>
HTML;
    }
    
    private function getHomeTemplate() {
        return <<<'HTML'
@extends('layout')

@section('content')
<div class="card">
    <h1 class="section-title">Drop-in Authentication System</h1>
    <p>A flexible user authentication system built with PHP, Bramus Router, SQLite, and BladeOne.</p>
    
    <div style="margin-top: 2rem;">
        @if(isset($isLoggedIn) && $isLoggedIn)
            <p>Welcome back, <strong>{{ $user['username'] }}</strong>!</p>
            <div style="margin-top: 1rem;">
                <a href="/dashboard" class="btn">Go to Dashboard</a>
            </div>
        @else
            <p>Please login or register to access your account.</p>
            <div style="margin-top: 1rem; display: flex; gap: 1rem;">
                <a href="/login" class="btn btn-outline">Login</a>
                <a href="/register" class="btn">Register</a>
            </div>
        @endif
    </div>
</div>

<div class="card">
    <h2 style="font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem;">Features</h2>
    <ul style="list-style-position: inside; margin-left: 1rem;">
        <li>User registration and authentication</li>
        <li>Secure password hashing</li>
        <li>Session management</li>
        <li>Rate limiting protection</li>
        <li>Responsive design</li>
        <li>Easy to integrate into any project</li>
    </ul>
</div>
@endsection
HTML;
    }
    
    private function getLoginTemplate() {
        return <<<'HTML'
@extends('layout')

@section('content')
<div class="card" style="max-width: 500px; margin: 0 auto;">
    <h1 class="section-title text-center">Login</h1>
    
    @if(isset($error))
        <div class="alert alert-error">
            {{ $error }}
        </div>
    @endif
    
    <form action="/login" method="post">
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn" style="width: 100%;">Login</button>
        </div>
    </form>
    
    <p class="text-center mt-4">
        Don't have an account? <a href="/register" style="color: var(--primary-color); text-decoration: none;">Register</a>
    </p>
</div>
@endsection
HTML;
    }
    
    private function getRegisterTemplate() {
        return <<<'HTML'
@extends('layout')

@section('content')
<div class="card" style="max-width: 500px; margin: 0 auto;">
    <h1 class="section-title text-center">Register</h1>
    
    @if(isset($error))
        <div class="alert alert-error">
            {{ $error }}
        </div>
    @endif
    
    <form action="/register" method="post">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
        </div>
        
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
        </div>
        
        <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
        </div>
        
        <div class="form-group">
            <button type="submit" class="btn" style="width: 100%;">Register</button>
        </div>
    </form>
    
    <p class="text-center mt-4">
        Already have an account? <a href="/login" style="color: var(--primary-color); text-decoration: none;">Login</a>
    </p>
</div>
@endsection
HTML;
    }
    
    private function getDashboardTemplate() {
        return <<<'HTML'
@extends('layout')

@section('content')
<div class="card">
    <h1 class="section-title">Welcome to your Dashboard</h1>
    <p>Hello, <strong>{{ $user['username'] }}</strong>! You are now logged in.</p>
</div>

<div class="card">
    <h2 style="font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem;">Your Account</h2>
    <p><strong>Username:</strong> {{ $user['username'] }}</p>
    <p><strong>Email:</strong> {{ $user['email'] }}</p>
    
    <div style="margin-top: 1.5rem;">
        <a href="/logout" class="btn" style="background-color: #ef4444; border-color: #ef4444;">Logout</a>
    </div>
</div>
@endsection
HTML;
    }
}

// Create app instance and run
$app = new App();
$app->run();