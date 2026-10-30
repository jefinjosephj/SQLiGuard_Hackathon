<?php
// Local-lab diagnostic only. The Compose port is bound to host loopback
// (127.0.0.1:8080), so REMOTE_ADDR inside Docker may be the Docker bridge
// gateway rather than 127.0.0.1. Do not publish this endpoint publicly.
mysqli_report(MYSQLI_REPORT_OFF);
$conn = @new mysqli('mysql', 'labuser', 'labpass', 'sqli_lab');
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

if ($conn->connect_error) {
    error_log('SQLiGuard DB diagnostic connection error: ' . $conn->connect_error);
    http_response_code(503);
    exit("SQLiGuard live database check: FAILED\nMySQL is not reachable from the web container.\n");
}
$result = $conn->query('SELECT COUNT(*) AS total FROM users');
if (!$result) {
    error_log('SQLiGuard DB diagnostic query error: ' . $conn->error);
    http_response_code(503);
    $conn->close();
    exit("SQLiGuard live database check: CONNECTED, QUERY FAILED\nCheck that the users table exists.\n");
}
$row = $result->fetch_assoc();
echo "SQLiGuard live database check: OK\n";
echo "Database: sqli_lab\n";
echo "Table: users\n";
echo "Demo records available: " . (int)$row['total'] . "\n";
echo "This page reports status only and does not display usernames or passwords.\n";
$conn->close();
?>
