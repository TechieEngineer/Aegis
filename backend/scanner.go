package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/aegis-project/aegis/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

type scanJob struct {
	ID       string          `json:"id"`
	Target   string          `json:"target"`
	Status   string          `json:"status"`
	Progress string          `json:"progress"`
	Created  time.Time       `json:"created_at"`
	Report   json.RawMessage `json:"report,omitempty"`
}

func (a *app) scanCreate(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	if p.Role != "Admin" && p.Role != "Analyst" {
		fail(w, 403, "analyst or admin required")
		return
	}
	if !a.limit(w, r, "scan:"+p.ID, 5) {
		return
	}
	var b struct {
		Target string `json:"target"`
	}
	if decode(r, &b) != nil {
		fail(w, 400, "target required")
		return
	}
	h, e := security.Host(b.Target, a.allowed)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if h != "demo.aegis.test" {
		ctx, c := context.WithTimeout(r.Context(), 5*time.Second)
		_, e = resolvePublic(ctx, h)
		c()
		if e != nil {
			fail(w, 400, "target DNS is unavailable or prohibited")
			return
		}
	}
	id, e := security.Random(18)
	if e != nil {
		fail(w, 500, "random source unavailable")
		return
	}
	tx, e := a.db.Begin(r.Context())
	if e != nil {
		fail(w, 503, "queue unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", p.ID); e != nil {
		fail(w, 503, "queue unavailable")
		return
	}
	var n int
	if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM scan_jobs WHERE owner_id=$1 AND status IN ('queued','running')", p.ID).Scan(&n); e != nil {
		fail(w, 503, "queue unavailable")
		return
	}
	if n >= 3 {
		fail(w, 429, "maximum three pending jobs")
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO scan_jobs(id,owner_id,target) VALUES($1,$2,$3)", id, p.ID, h); e != nil {
		fail(w, 503, "queue unavailable")
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		fail(w, 503, "queue unavailable")
		return
	}
	_ = a.rdb.LPush(r.Context(), "recon:queue", id).Err()
	reply(w, 202, map[string]string{"id": id, "status": "queued"})
}
func (a *app) scanList(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query(r.Context(), "SELECT id,target,status,progress,created_at FROM scan_jobs WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 50", who(r).ID)
	if e != nil {
		fail(w, 500, "jobs unavailable")
		return
	}
	defer rows.Close()
	out := []scanJob{}
	for rows.Next() {
		var j scanJob
		if e = rows.Scan(&j.ID, &j.Target, &j.Status, &j.Progress, &j.Created); e != nil {
			fail(w, 500, "jobs unavailable")
			return
		}
		out = append(out, j)
	}
	if rows.Err() != nil {
		fail(w, 500, "jobs unavailable")
		return
	}
	reply(w, 200, out)
}
func (a *app) job(ctx context.Context, id, owner string) (scanJob, error) {
	var j scanJob
	var raw []byte
	e := a.db.QueryRow(ctx, `SELECT j.id,j.target,j.status,j.progress,j.created_at,r.report FROM scan_jobs j LEFT JOIN scan_reports r ON j.id=r.job_id WHERE j.id=$1 AND j.owner_id=$2`, id, owner).Scan(&j.ID, &j.Target, &j.Status, &j.Progress, &j.Created, &raw)
	if raw != nil {
		j.Report = raw
	}
	return j, e
}
func (a *app) scanGet(w http.ResponseWriter, r *http.Request) {
	j, e := a.job(r.Context(), chi.URLParam(r, "id"), who(r).ID)
	if errors.Is(e, pgx.ErrNoRows) {
		fail(w, 404, "job not found")
		return
	}
	if e != nil {
		fail(w, 500, "job unavailable")
		return
	}
	reply(w, 200, j)
}
func (a *app) scanEvents(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	id := chi.URLParam(r, "id")
	j, e := a.job(r.Context(), id, p.ID)
	if e != nil {
		fail(w, 404, "job unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, "streaming unavailable")
		return
	}
	ctx, c := context.WithTimeout(r.Context(), 120*time.Second)
	defer c()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store, no-transform")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	last := ""
	for {
		state, e := a.rdb.HGetAll(ctx, "session:"+p.Family).Result()
		if e != nil || state["uid"] != p.ID || state["revoked"] == "1" {
			return
		}
		if j.Status+":"+j.Progress != last {
			raw, e := json.Marshal(j)
			if e != nil {
				return
			}
			if _, e = fmt.Fprintf(w, "data: %s\n\n", raw); e != nil {
				return
			}
			flusher.Flush()
			last = j.Status + ":" + j.Progress
		}
		if j.Status == "completed" || j.Status == "failed" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		j, e = a.job(ctx, id, p.ID)
		if e != nil {
			return
		}
	}
}
func resolvePublic(ctx context.Context, h string) ([]netip.Addr, error) {
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", h+".")
	if e != nil || len(ips) == 0 {
		return nil, errors.New("DNS lookup failed")
	}
	for _, ip := range ips {
		if !security.PublicIP(ip) {
			return nil, errors.New("non-public address in DNS answer")
		}
	}
	return ips, nil
}
func (a *app) scanWorker(ctx context.Context) {
	for ctx.Err() == nil { // Redis is a wake-up queue; PostgreSQL is the durable source of truth.
		_, _ = a.rdb.BRPop(ctx, 2*time.Second, "recon:queue").Result()
		if ctx.Err() != nil {
			return
		}
		var id, h string
		e := a.db.QueryRow(ctx, `UPDATE scan_jobs SET status='running',progress='Validating scope',updated_at=now() WHERE id=(SELECT id FROM scan_jobs WHERE status='queued' OR (status='running' AND updated_at<now()-interval '3 minutes') ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,target`).Scan(&id, &h)
		if e != nil {
			if !errors.Is(e, pgx.ErrNoRows) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
			continue
		}
		run, c := context.WithTimeout(ctx, 45*time.Second)
		report, e := a.inspect(run, id, h)
		c()
		if ctx.Err() != nil {
			return
		}
		save, done := context.WithTimeout(ctx, 5*time.Second)
		if e != nil {
			_, _ = a.db.Exec(save, "UPDATE scan_jobs SET status='failed',progress=$1,updated_at=now() WHERE id=$2", e.Error(), id)
			done()
			continue
		}
		raw, e := json.Marshal(report)
		if e == nil {
			tx, err := a.db.Begin(save)
			if err == nil {
				_, err = tx.Exec(save, "INSERT INTO scan_reports(job_id,report) VALUES($1,$2::jsonb) ON CONFLICT(job_id) DO UPDATE SET report=excluded.report", id, string(raw))
				if err == nil {
					_, err = tx.Exec(save, "UPDATE scan_jobs SET status='completed',progress='Report ready',updated_at=now() WHERE id=$1", id)
				}
				if err == nil {
					err = tx.Commit(save)
				}
				_ = tx.Rollback(save)
				if err != nil {
					_, _ = a.db.Exec(save, "UPDATE scan_jobs SET status='failed',progress='Report storage failed',updated_at=now() WHERE id=$1", id)
				}
			}
		}
		done()
	}
}
func (a *app) progress(ctx context.Context, id, msg string) {
	_, _ = a.db.Exec(ctx, "UPDATE scan_jobs SET progress=$1,updated_at=now() WHERE id=$2", msg, id)
}
func (a *app) inspect(ctx context.Context, id, h string) (map[string]any, error) {
	if _, e := security.Host(h, a.allowed); e != nil {
		return nil, errors.New("target no longer approved")
	}
	if h == "demo.aegis.test" {
		for _, msg := range []string{"Checking simulated DNS records", "Checking simulated HTTPS certificate", "Checking simulated HTTP security headers"} {
			a.progress(ctx, id, msg)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(1500 * time.Millisecond):
			}
		}
		return map[string]any{"mode": "offline simulation — no network traffic", "host": h, "dns": map[string]any{"A": []string{"192.0.2.10"}, "AAAA": []string{"2001:db8::10"}, "MX": []string{"10 mail.demo.aegis.test"}, "TXT": []string{"v=spf1 -all"}, "NS": []string{"ns.demo.aegis.test"}}, "tls": map[string]any{"issuer": "Aegis Demo CA (fictional)", "expires": "2030-01-01T00:00:00Z", "cipher": "TLS_AES_128_GCM_SHA256"}, "ports": map[string]any{"80": "simulated open", "443": "simulated open"}, "headers": map[string]string{"Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "missing", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}}, nil
	}
	a.progress(ctx, id, "Resolving approved hostname")
	d, c := context.WithTimeout(ctx, 5*time.Second)
	ips, e := resolvePublic(d, h)
	c()
	if e != nil {
		return nil, e
	} // Pin each connection to one vetted address; no redirects or proxy.
	ip := ips[0].Unmap().String()
	dns := map[string]any{}
	v4, v6 := []string{}, []string{}
	for _, x := range ips {
		if x.Unmap().Is4() {
			v4 = append(v4, x.Unmap().String())
		} else {
			v6 = append(v6, x.String())
		}
	}
	dns["A"] = v4
	dns["AAAA"] = v6
	d, c = context.WithTimeout(ctx, 5*time.Second)
	if v, e := net.DefaultResolver.LookupMX(d, h+"."); e == nil {
		dns["MX"] = v
	}
	if v, e := net.DefaultResolver.LookupTXT(d, h+"."); e == nil {
		dns["TXT"] = v
	}
	if v, e := net.DefaultResolver.LookupNS(d, h+"."); e == nil {
		dns["NS"] = v
	}
	c()
	a.progress(ctx, id, "Checking approved web endpoints")
	ports := map[string]string{}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	for _, port := range []string{"80", "443"} {
		conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		if e == nil {
			ports[port] = "open"
			conn.Close()
		} else {
			ports[port] = "not reachable"
		}
	}
	a.progress(ctx, id, "Inspecting TLS and HTTP security headers")
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10, DisableKeepAlives: true, DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil || !strings.EqualFold(host, h) || port != "443" {
			return nil, errors.New("unexpected destination")
		}
		return dialer.DialContext(c, "tcp", net.JoinHostPort(ip, port))
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "HEAD", "https://"+h+"/", nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "Aegis-Authorized-Audit/1.0")
	report := map[string]any{"mode": "approved live web audit", "host": h, "pinned_ip": ip, "dns": dns, "ports": ports}
	resp, e := client.Do(req)
	if e != nil {
		report["https_error"] = "TLS verification or HTTPS request failed"
		return report, nil
	}
	defer resp.Body.Close()
	headers := map[string]string{}
	for _, k := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
		v := resp.Header.Get(k)
		if v == "" {
			v = "missing"
		}
		if len(v) > 2048 {
			v = v[:2048]
		}
		headers[k] = v
	}
	report["headers"] = headers
	report["http_status"] = resp.StatusCode
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		report["tls"] = map[string]any{"issuer": cert.Issuer.String(), "subject": cert.Subject.String(), "expires": cert.NotAfter, "cipher": tls.CipherSuiteName(resp.TLS.CipherSuite), "version": resp.TLS.Version}
	}
	return report, nil
}
