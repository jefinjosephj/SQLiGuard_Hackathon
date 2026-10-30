<?php

$host = "mysql";
$user = "labuser";
$password = "labpass";
$database = "sqli_lab";

$conn = new mysqli($host, $user, $password, $database);

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$username = $_POST["username"] ?? "";
$password_input = $_POST["password"] ?? "";

/*
 * INTENTIONALLY VULNERABLE
 * User input is directly concatenated into the SQL query.
 */

$sql = "SELECT id, username FROM users WHERE username = '$username' AND password = '$password_input'";

echo "<h3>Generated Query</h3>";
echo "<pre>" . htmlspecialchars($sql) . "</pre>";

$result = $conn->query($sql);

if ($result === false) {
    echo "<h2>SQL Error</h2>";
    echo "<pre>" . htmlspecialchars($conn->error) . "</pre>";
    $conn->close();
    exit;
}

if ($result->num_rows > 0) {

    $row = $result->fetch_assoc();

    echo "<h2>Login successful</h2>";
    echo "<p>Welcome, " . htmlspecialchars($row["username"]) . "!</p>";

} else {

    echo "<h2>Login failed</h2>";
    echo "<p>Invalid username or password.</p>";

}

$conn->close();

?>