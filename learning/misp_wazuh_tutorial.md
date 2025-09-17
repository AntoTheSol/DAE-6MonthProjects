# 📘 Mini-Tutorial: MISP Integration with Wazuh SIEM

_A student-authored tutorial documenting automated threat intelligence enrichment for security operations._

---

## ❓ What This Teaches

**MISP (Malware Information Sharing Platform) integration with Wazuh SIEM enables automated IoC enrichment and threat intelligence correlation.** Instead of manually looking up suspicious IPs, domains, or file hashes from security alerts, MISP automatically cross-references them against community threat databases, providing instant context and reducing investigation time from minutes to seconds. This transforms reactive alert processing into proactive, intelligence-driven security operations with enhanced alert quality, faster incident response, and reduced alert fatigue.

---

## 🎯 Use Case

> What real-world need or job scenario does this apply to?

- [x] **Cybersecurity**: SOC analysts, threat hunters, incident responders
- [x] **Monitoring / Observability**: Security monitoring, threat detection pipelines
- [x] Performance / Testing
- [x] Authentication / Authorization

**Key Benefits:**
- **Automated IOC enrichment** - Alerts come pre-loaded with threat context
- **Community intelligence** - Benefit from threat sharing with other organizations
- **Pivot capabilities** - Jump from one indicator to related threats quickly
- **Pre-built threat profiles** - Instant access to known TTPs for faster analysis

---

## 🚀 Quick Setup / Install

Show just what's needed to get started.

```bash
# Prerequisites: Docker Desktop running, Wazuh already installed
cd Desktop
git clone https://github.com/misp/misp-docker
cd misp-docker

# Pull and start containers
docker-compose pull
docker-compose up -d
```

**Default credentials:** `admin@admin.test` / `admin`

---

## 🛠️ Step-by-Step Guide

### Phase 1: Initial Configuration

1. **Fix port conflict with Wazuh (port 443):**

    Edit `docker-compose.yml` under `misp-core` service:
    ```yaml
    ports:
      - "80:80"
      - "444:443"  # Changed from 443:443 to avoid Wazuh conflict
    ```

2. **Configure environment variables:**

    Edit `.env` file:
    ```bash
    BASE_URL=https://localhost:444
    CORE_RUNNING_TAG=latest
    
    # Redis configuration
    REDIS_HOST=redis
    REDIS_PORT=6379
    REDIS_PASSWORD=redispassword
    ```

3. **Initial startup attempt:**
    ```bash
    docker-compose up -d
    ```

### Phase 2: Troubleshooting Common Issues

**Issue 1: Permission Errors**

If you see: `Warning Error: copy(/var/www/MISP/app/Config/config.backup.php): Failed to open stream: Permission denied`

**Solution - Clean restart with proper permissions:**
```bash
# Stop and clean environment
docker-compose down -v
docker system prune -f

# Reset directory structure with correct ownership
sudo rm -rf configs logs files ssl gnupg
mkdir -p configs logs files ssl gnupg
sudo chown -R 33:33 configs logs files gnupg ssl  # UID 33 = www-data

# Fresh start
docker-compose up -d
```

**Issue 2: Authentication Keys Redis Error**

If authentication keys page shows internal error:

```bash
# Configure general MISP Redis settings
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting MISP.redis_host redis
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting MISP.redis_password redispassword
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting MISP.redis_port 6379
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting MISP.redis_database 13

# Fix config backup file permissions
docker exec misp-docker-misp-core-1 touch /var/www/MISP/app/Config/config.backup.php
docker exec misp-docker-misp-core-1 chown www-data:www-data /var/www/MISP/app/Config/config.backup.php
```

**Issue 3: Feed Processing Errors**

If feeds fail to enable/fetch (background job errors):

```bash
# Configure background jobs Redis (separate from general Redis)
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting SimpleBackgroundJobs.redis_host redis
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting SimpleBackgroundJobs.redis_password redispassword
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting SimpleBackgroundJobs.redis_port 6379
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting SimpleBackgroundJobs.redis_database 1
docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin setSetting SimpleBackgroundJobs.enabled true

# Restart to apply changes
docker restart misp-docker-misp-core-1
```

### Phase 3: Automation Setup

4. **Generate API key for automation:**
   - Log into MISP at `https://localhost:444`
   - Navigate to **Administration** → **List Auth Keys**
   - Click **Add authentication key**
   - Comment: `Daily Feed Automation`
   - Copy the generated API key

5. **Set up automated daily feed sync:**

    ```bash
    # Test API call first
    curl -XPOST --insecure \
      --header "Authorization: YOUR_API_KEY" \
      --header "Accept: application/json" \
      --header "Content-Type: application/json" \
      https://localhost:444/feeds/fetchFromAllFeeds

    # Add to crontab for daily sync at 1:00 AM
    sudo crontab -e
    ```
    
    Add this line:
    ```bash
    0 1 * * * /usr/bin/curl -XPOST --insecure --header "Authorization: YOUR_API_KEY" --header "Accept: application/json" --header "Content-Type: application/json" https://localhost:444/feeds/fetchFromAllFeeds
    ```

---

## ✅ What You Should See

**Successful deployment indicators:**

- **MISP Dashboard**: Accessible at `https://localhost:444` with default login
- **Authentication Keys**: Page loads without internal server errors
- **Redis Verification**: 
  ```bash
  docker exec misp-docker-misp-core-1 /var/www/MISP/app/Console/cake admin getSetting MISP.redis_host
  # Returns: {"value": "redis", "errorMessage": null, "setting": "MISP.redis_host"}
  ```
- **Feed Management**: Feeds can be enabled and fetch successfully
- **Background Jobs**: Process without errors
- **Automated Sync**: Cron job returns `{"result": "Pull queued for background execution."}`

**File ownership check:**
```bash
ls -la configs logs files gnupg ssl
# Should show: drwxr-xr-x 33 33 (or www-data www-data)
```

---

## 💡 Pro Tips / Edge Cases

**Critical Architecture Understanding:**
- **Dual Redis Setup**: MISP uses separate Redis configurations for general operations (`MISP.redis_*`) and background jobs (`SimpleBackgroundJobs.redis_*`). Both must be configured even when using the same Redis instance.
- **Container UID**: MISP container runs as `www-data` (UID 33), so mounted volumes need `chown -R 33:33` or permission cascades will fail.
- **Environment vs Internal Config**: Docker `.env` variables don't automatically sync with MISP's internal database settings - you must configure both.

**Troubleshooting Dependencies:**
Feed functionality chain: `Authentication Keys → General Redis → Background Jobs Redis → SimpleBackgroundJobs.enabled`. All components must work for complete functionality.

**Security Considerations:**
- Keep API keys secure and don't commit to version control
- Consider IP restrictions for production API keys
- Use proper SSL certificates instead of `--insecure` flag in production

---

## 📚 Learn More

- [MISP Official Documentation](https://www.misp-project.org/documentation/)
- [MISP-Docker Repository](https://github.com/misp/misp-docker)
- [Wazuh MISP Integration](https://documentation.wazuh.com/current/user-manual/capabilities/threat-detection/threat-intelligence.html)
- [MISP API Documentation](https://www.misp-project.org/openapi/)

---

## 👤 Authored by: Gabriel Zepeda

🗓️ Date: 2025-09-17  
🔁 Validated by: [Educator or Peer Name if applicable]