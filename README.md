# SQLiGuard — SQL Injection Detection and Prevention Framework

## 1. Project Overview

SQLiGuard is a local educational project that demonstrates SQL injection vulnerabilities and compares vulnerable and secured PHP/MySQL login systems.

It uses a Python test runner to perform 10 HTTP behavior tests and 4 source-level security checks. The results are saved as JSON and HTML reports.

## 2. Project Components

* `web/vulnerable_frontend.html` — Interface for the vulnerable login system.
* `web/vulnerable_login.php` — Intentionally vulnerable login endpoint for local testing.
* `web/sql_frontend.html` — Interface for the secured login system.
* `web/login.php` — Secured login endpoint using parameterized queries.
* `test_runner.py` — Runs 14 automated checks and generates reports.
* `sqli_db.sql` — Demonstration database and sample data.
* `docker-compose.yml` and `web/Dockerfile` — Set up the local environment.

## 3. Requirements

* Docker Desktop with Docker Compose
* Python 3.9 or later
* Web browser

## 4. How to Run

Open PowerShell or Command Prompt in the project folder containing `docker-compose.yml`.

Start the application:

```powershell
docker compose up --build -d
```

Check the services:

```powershell
docker compose ps
```

Open the applications in your browser:

* **Vulnerable login:** http://localhost:8080/vulnerable_frontend.html
* **Secured login:** http://localhost:8080/sql_frontend.html

Run the automated tests:

```powershell
python test_runner.py
```

Open the HTML report:

```powershell
Start-Process .\evidence\test_report.html
```

The generated reports are:

* `evidence/test_report.html`
* `evidence/test_results.json`

Stop the application:

```powershell
docker compose down
```

To delete the demonstration database volume as well, run `docker compose down -v` only if you intend to erase its stored data.

## 5. Testing

SQLiGuard includes 14 checks.

### HTTP Behavior Tests

| Test | Description                                              |
| ---- | -------------------------------------------------------- |
| T01  | Valid credentials on the vulnerable endpoint             |
| T02  | Invalid credentials on the vulnerable endpoint           |
| T03  | Controlled SQL injection test on the vulnerable endpoint |
| T04  | Valid credentials on the secured endpoint                |
| T05  | Invalid credentials on the secured endpoint              |
| T06  | SQL injection test on the secured endpoint               |
| T07  | Empty credentials                                        |
| T08  | Username containing only a quotation mark                |
| T09  | SQL-like special characters in the username              |
| T10  | Whitespace-only credentials                              |

### Source-Level Checks

The test runner checks whether the secured PHP code contains indicators of:

* Parameterized queries and `bind_param`.
* HTML output escaping.
* Generic database error handling and server-side logging.
* Generic authentication failure messages.

## 6. Expected Results

* Valid sample credentials should work on both endpoints.
* Invalid credentials should be rejected.
* The controlled injection test should demonstrate the expected weakness in the vulnerable endpoint.
* The secured endpoint should reject the same injection attempt.
* The test runner should generate HTML and JSON reports.

**Note:** These are expected results. Actual outcomes must be confirmed by running the tests.

## 7. Security Features

The secured endpoint demonstrates:

* Parameterized SQL queries.
* Generic error messages.
* Server-side error logging.
* HTML output escaping.

The test runner is designed to restrict targets to loopback addresses and defaults to `127.0.0.1:8080`.

The demonstration database uses plaintext sample passwords, so this project must not be used with real credentials or exposed publicly.

## 8. Limitations

* The project focuses on one login workflow.
* It is not a general-purpose SQL injection scanner.
* Source-level checks do not prove that the application is completely secure.
* Password hashing and least-privilege database permissions are future improvements.

## 9. Team Responsibilities

**Member 1 - Application Development**

* Explain the PHP/MySQL application.
* Demonstrate the vulnerable and secured login systems.
* Explain parameterized queries.

**Member 2 - Testing**

* Run the Python test suite.
* Explain the 14 checks.
* Review the HTML and JSON reports.

**Member 3 - Documentation and Presentation**

* Prepare project documentation and slides.
* Explain the architecture and test results.
* Present limitations and future improvements.


## 10. Conclusion

SQLiGuard demonstrates how SQL injection vulnerabilities can affect login systems and how parameterized queries help prevent them.

By comparing vulnerable and secured implementations and running automated tests, the project provides a simple way to understand SQL injection prevention and evaluate selected security controls in a controlled local environment.

**Project scope:** Educational demonstration and authorized local testing only.
