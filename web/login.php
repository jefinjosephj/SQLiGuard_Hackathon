<?php
// Secured demonstration endpoint. Local hackathon lab only; not production auth.
mysqli_report(MYSQLI_REPORT_OFF);
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method not allowed.');
}

$host = 'mysql';
$db_user = 'labuser';
$db_password = 'labpass';
$database = 'sqli_lab';

$conn = @new mysqli($host, $db_user, $db_password, $database);
if ($conn->connect_error) {
    error_log('SQLiGuard database connection error: ' . $conn->connect_error);
    http_response_code(503);
    exit('Service temporarily unavailable.');
}
if (!$conn->set_charset('utf8mb4')) {
    error_log('SQLiGuard character-set setup failed: ' . $conn->error);
    http_response_code(503);
    $conn->close();
    exit('Service temporarily unavailable.');
}

$username = (isset($_POST['username']) && is_string($_POST['username']))
    ? trim($_POST['username']) : '';
$password_input = (isset($_POST['password']) && is_string($_POST['password']))
    ? $_POST['password'] : '';

if ($username === '' || $password_input === '') {
    http_response_code(401);
    echo '<h2>Login failed</h2>';
    echo '<p>Invalid username or password.</p>';
    $conn->close();
    exit;
}

// PREVENTION CONTROL: bound values are treated as data, not SQL syntax.
$sql = 'SELECT id, username FROM users WHERE username = ? AND password = ?';
$stmt = $conn->prepare($sql);
if (!$stmt) {
    error_log('SQLiGuard statement preparation failed: ' . $conn->error);
    http_response_code(503);
    $conn->close();
    exit('Service temporarily unavailable.');
}

if (!$stmt->bind_param('ss', $username, $password_input) || !$stmt->execute()) {
    error_log('SQLiGuard login query execution failed: ' . $stmt->error);
    http_response_code(503);
    $stmt->close();
    $conn->close();
    exit('Service temporarily unavailable.');
}

$result = $stmt->get_result();
if ($result && $result->num_rows > 0) {
    echo '<h2>Login successful</h2>';
    echo '<p>Welcome, ' . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . '!</p>';
} else {
    http_response_code(401);
    echo '<h2>Login failed</h2>';
    echo '<p>Invalid username or password.</p>';
}

$stmt->close();
$conn->close();
?>
