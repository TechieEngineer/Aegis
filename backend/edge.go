package main

import (
	"bytes"
	"context"
	"github.com/aegis-project/aegis/internal/security"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var rateScript = redis.NewScript(`
local clock=redis.call('TIME')
local now=tonumber(clock[1])*1000+math.floor(tonumber(clock[2])/1000)
local window=60000
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-window)
local n=redis.call('ZCARD',KEYS[1])
local limit=tonumber(ARGV[1])
local allowed=0
if n<limit then redis.call('ZADD',KEYS[1],now,ARGV[2]); n=n+1; allowed=1 end
redis.call('PEXPIRE',KEYS[1],window)
local oldest=redis.call('ZRANGE',KEYS[1],0,0,'WITHSCORES')
local reset=math.ceil((tonumber(oldest[2] or now)+window)/1000)
return {allowed,limit-n,reset,math.max(1,reset-math.floor(now/1000))}
`)

func (a *app) ip(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	if host == a.proxyIP {
		if ip, e := netip.ParseAddr(r.Header.Get("X-Real-IP")); e == nil {
			return ip.Unmap().String()
		}
	}
	return host
}
func (a *app) limit(w http.ResponseWriter, r *http.Request, k string, max int) bool {
	nonce, e := security.Random(16)
	if e != nil {
		fail(w, 503, "limiter unavailable")
		return false
	}
	v, e := rateScript.Run(r.Context(), a.rdb, []string{"rate:" + k}, max, nonce).Int64Slice()
	if e != nil || len(v) != 4 {
		fail(w, 503, "limiter unavailable")
		return false
	}
	w.Header().Set("X-RateLimit-Limit", number(int64(max)))
	w.Header().Set("X-RateLimit-Remaining", number(v[1]))
	w.Header().Set("X-RateLimit-Reset", number(v[2]))
	if v[0] == 0 {
		w.Header().Set("Retry-After", number(v[3]))
		fail(w, 429, "rate limit exceeded")
		return false
	}
	return true
}
func (a *app) authRate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.limit(w, r, "auth:"+a.ip(r), 15) {
			next.ServeHTTP(w, r)
		}
	})
}
func (a *app) blocked(w http.ResponseWriter, r *http.Request, rule string) {
	select {
	case a.audit <- auditEvent{rule, r.Method}:
	default:
		log.Print("WAF audit queue saturated; event dropped")
	}
	fail(w, 403, "request blocked by WAF: "+rule)
}
func (a *app) edge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(a.origin, "https://") {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if o := r.Header.Get("Origin"); (o != "" && o != a.origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				fail(w, 403, "cross-origin request denied")
				return
			}
		}
		if !a.limit(w, r, "ip:"+a.ip(r), 120) {
			return
		}
		if r.URL.Path == "/api/probe" && !a.limit(w, r, "probe:"+a.ip(r), 20) {
			return
		}
		if rule := security.Inspect(r.URL.EscapedPath()); rule != "" {
			a.blocked(w, r, rule)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			fail(w, 400, "invalid query encoding")
			return
		}
		for k, values := range query {
			if rule := security.Inspect(k); rule != "" {
				a.blocked(w, r, rule)
				return
			}
			for _, v := range values {
				if rule := security.Inspect(v); rule != "" {
					a.blocked(w, r, rule)
					return
				}
			}
		}
		for k, values := range r.Header {
			switch strings.ToLower(k) {
			case "cookie", "authorization", "referer", "origin":
				continue
			}
			for _, v := range values {
				if rule := security.Inspect(v); rule != "" {
					a.blocked(w, r, rule)
					return
				}
			}
		}
		if r.Body != nil && r.Body != http.NoBody {
			body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
			r.Body.Close()
			if e != nil {
				fail(w, 413, "request body too large or unreadable")
				return
			}
			if len(body) > 0 {
				if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
					fail(w, 415, "compressed request bodies not accepted")
					return
				}
				typ, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if typ != "application/json" {
					fail(w, 415, "application/json required")
					return
				}
				if rule := security.InspectBody(body); rule != "" {
					a.blocked(w, r, rule)
					return
				}
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}
func (a *app) auditWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case v := <-a.audit:
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, e := a.db.Exec(c, "INSERT INTO waf_audit_logs(rule,method) VALUES($1,$2)", v.Rule, v.Method)
			cancel()
			if e != nil {
				log.Print("WAF audit write failed")
			}
		}
	}
}
func (a *app) telemetry(w http.ResponseWriter, r *http.Request) {
	if who(r).Role != "Admin" {
		fail(w, 403, "admin required")
		return
	}
	rows, e := a.db.Query(r.Context(), "SELECT rule,count(*) FROM waf_audit_logs WHERE occurred_at>now()-interval '24 hours' GROUP BY rule ORDER BY rule")
	if e != nil {
		fail(w, 500, "telemetry unavailable")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var rule string
		var count int64
		if e = rows.Scan(&rule, &count); e != nil {
			fail(w, 500, "telemetry unavailable")
			return
		}
		out = append(out, map[string]any{"rule": rule, "count": count})
	}
	if rows.Err() != nil {
		fail(w, 500, "telemetry unavailable")
		return
	}
	reply(w, 200, out)
}
