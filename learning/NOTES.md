# Observability & Logging: Project Notes

This document tracks your progress and implementation of observability features in your backend or cybersecurity project. You will update this continuously as you build health checks, logs, and metrics.

---

## 1. Health Check Endpoint

**Have you implemented a health-check endpoint?**  
(Replace `[ ]` with `[x]`)

-   [ ] Yes
-   [ ] No
-   [ ] Not applicable to my project

**Your endpoint path:**  
Example: `/health`, `/status`, `/api/v1/status`

```
# Sample output (if applicable):
{
  "status": "ok",
  "uptime": "2053s",
  "version": "1.0.2"
}
```

**Why is this useful?**  
Write 1-2 sentences explaining why you added this endpoint:

> Example: Allows external systems to check if the service is running and responsive without accessing internal logic.

---

## 2. Health Check Test

**Did you write a test for the health-check endpoint?**

-   [ ] Yes
-   [ ] No

**Paste your test code or description here:**

```
# Example in Python (FastAPI + pytest)
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
```

---

## 3. Log Event or Metric

**Name of log event or metric:**  
Example: `"user_login_success"`, `"unauthorized_attempt"`, `"system_heartbeat"`

**What triggers this?**  
Example: Each time a user logs in, or every 5 minutes for uptime tracking.

**Sample output format or log:**

```
# Example (JSON log)
{
  "event": "unauthorized_attempt",
  "ip": "192.168.1.101",
  "timestamp": "2025-09-15T14:31:24Z"
}
```

**Where is this implemented in your code?**  
Mention the file and function. Example: `auth/login.py → handle_login()`

---

## 4. Optional Monitoring Tools

Only fill this out if you added any external monitoring.

**Did you use monitoring tools (e.g. Grafana, Prometheus, Kibana)?**

-   [ ] Yes
-   [ ] No

**Tool name(s):**  
Example: Grafana dashboard for memory usage and uptime.

**Screenshot or description of what the tool shows:**

```
# Example description:
Dashboard displays request count, error rate, and memory usage over time.
```

---

## 5. Reflection & Learning

**What did you learn while implementing observability in your project?**

> Example: I learned that structured logging helps track real user activity and makes error detection easier.

**Anything you would do differently or improve in the future?**

> Example: I would log more internal actions, like database queries and job status.

---
