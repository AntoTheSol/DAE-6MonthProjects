# 🧪 Mock Interview Questions & Answers

This file is a living document of technical and reflective questions based on my Semester 5 self-learning and integration project.  
Use it to prepare for real interviews, practice answering out loud, and reflect on how to explain your work clearly and confidently.

You may include:

-   Code snippets
-   Output logs
-   Screenshots (as image links)
-   Architecture sketches
-   Performance comparisons
-   Anything that helps you **communicate clearly** what you learned and built

---

## 📌 How to Use This File

-   Start with the **question** as a heading (e.g. `## What problem were you trying to solve?`)
-   Under each, write a clear, concise **answer**
-   Use bullet points, diagrams, or code when helpful
-   Each answer should reflect your own learning and implementation

---

## ✅ Example Entry

### What new technology did you learn and why?

I chose **OpenTelemetry** for distributed tracing in my backend API. It helps track how requests move through services, and I wanted to improve observability for debugging and performance.

**Why this tech:**

-   Job-aligned: Many job postings for backend roles mention observability, tracing, or metrics.
-   Project fit: My capstone has multiple services that could benefit from request tracking.
-   Personal gap: I had never set up distributed tracing before.

---

### How did you integrate it into your project?

1. Chose `opentelemetry-python` SDK
2. Configured tracing middleware for FastAPI
3. Exported traces to local `jaeger` instance
4. Added a custom span for one high-cost function

```python
with tracer.start_as_current_span("db_query"):
    result = expensive_query()
```

---

### What was the most difficult part?

-   Understanding how to propagate context across async calls
-   Fixing an issue where traces weren’t showing in Jaeger due to exporter misconfig
-   I solved this by enabling debug logging and reading OpenTelemetry's SDK source

---

### Show an example of test output or trace evidence

```bash
pytest tests/
================ 5 passed in 0.14s =================

Trace ID: 8cf29c1dbed3a5f4
Span: GET /api/search -> db_query -> response_sent
```

---

### What tradeoffs or alternatives did you consider?

-   Considered Prometheus metrics but wanted request-level traces
-   OpenTelemetry had more setup steps, but long-term better for tracing granularity

---

### How would you improve this integration?

-   Automate tracing setup in CI
-   Add sampling rules to avoid trace spam
-   Visualize traces in Grafana

---

## 🧱 Entry Template (copy this section for each question)

### What is the question?

_Your answer goes here._  
You can use:

-   Bullet points
-   Snippets:
    ```python
    # code
    ```
-   Output:
    ```bash
    # logs or test results
    ```
-   Links to relevant PRs, branches, screenshots, or diagrams

---

### Another example question to include:

-   How did you verify your integration worked?
-   What metrics, logs, or test outputs did you use?
-   What edge case did you handle or miss?
-   How does this tech compare to another you considered?

---

## 🧠 Tips

-   Try writing 5–10 Q&A entries total.
-   Answer as if a technical interviewer asked you, or your future self reviewing this later.
-   Don’t just say what worked — also say what was hard, weird, or surprising.

---

_Last updated: [add date here]_
