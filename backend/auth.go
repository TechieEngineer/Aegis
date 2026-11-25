package main

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/aegis-project/aegis/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

const sessionTTL = 7 * 24 * time.Hour

var rotateScript = redis.NewScript(`
local k=KEYS[1]
if redis.call('EXISTS',k)==0 or redis.call('HGET',k,'revoked')=='1' then return 'invalid' end
local state=redis.call('HGET',k,'t:'..ARGV[1])
if state=='used' then redis.call('HSET',k,'revoked','1'); return 'replay' end
if state~='active' then return 'invalid' end
local n=tonumber(redis.call('HGET',k,'count') or '0')
if n>=2048 then redis.call('HSET',k,'revoked','1'); return 'invalid' end
redis.call('HSET',k,'t:'..ARGV[1],'used','t:'..ARGV[2],'active','count',n+1)
return redis.call('HGET',k,'uid')
`)

func (a *app) newSession(ctx context.Context, id string) (string, string, error) {
	family, e := security.Random(24)
	if e != nil {
		return "", "", e
	}
	token, e := security.Random(32)
	if e != nil {
		return "", "", e
	}
	access, e := a.access(id, family)
	if e != nil {
		return "", "", e
	}
	_, e = a.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, "session:"+family, "uid", id, "revoked", "0", "count", 0, "t:"+digest(token), "active")
		p.Expire(ctx, "session:"+family, sessionTTL)
		return nil
	})
	return access, family + "." + token, e
}
func (a *app) cookies(w http.ResponseWriter, access, refresh string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: "aegis_access", Value: access, Path: "/api", MaxAge: 900, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "aegis_refresh", Value: refresh, Path: "/api/auth", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}
func clearCookies(w http.ResponseWriter) {
	for _, v := range []struct{ n, p string }{{"aegis_access", "/api"}, {"aegis_refresh", "/api/auth"}} {
		http.SetCookie(w, &http.Cookie{Name: v.n, Path: v.p, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	}
}
func refreshParts(r *http.Request) (string, string, bool) {
	c, e := r.Cookie("aegis_refresh")
	if e != nil {
		return "", "", false
	}
	p := strings.Split(c.Value, ".")
	if len(p) != 2 || len(p[0]) != 32 || len(p[1]) != 43 {
		return "", "", false
	}
	return p[0], p[1], true
}
func (a *app) refresh(w http.ResponseWriter, r *http.Request) {
	family, old, ok := refreshParts(r)
	if !ok {
		fail(w, 401, "refresh token required")
		return
	}
	fresh, e := security.Random(32)
	if e != nil {
		fail(w, 500, "random source unavailable")
		return
	}
	result, e := rotateScript.Run(r.Context(), a.rdb, []string{"session:" + family}, digest(old), digest(fresh)).Text()
	if e != nil {
		fail(w, 503, "session store unavailable")
		return
	}
	if result == "invalid" || result == "replay" {
		clearCookies(w)
		fail(w, 401, "session invalid or revoked; sign in again")
		return
	}
	access, e := a.access(result, family)
	if e != nil {
		fail(w, 500, "token signing failed")
		return
	}
	ttl, e := a.rdb.TTL(r.Context(), "session:"+family).Result()
	if e != nil || ttl < time.Second {
		clearCookies(w)
		fail(w, 401, "session expired")
		return
	}
	a.cookies(w, access, family+"."+fresh, ttl)
	reply(w, 200, map[string]bool{"ok": true})
}

var logoutScript = redis.NewScript(`if redis.call('HEXISTS',KEYS[1],'t:'..ARGV[1])==1 then redis.call('HSET',KEYS[1],'revoked','1') end return 1`)

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	family, token, ok := refreshParts(r)
	if ok {
		if e := logoutScript.Run(r.Context(), a.rdb, []string{"session:" + family}, digest(token)).Err(); e != nil {
			fail(w, 503, "session store unavailable")
			return
		}
	}
	clearCookies(w)
	reply(w, 200, map[string]bool{"ok": true})
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

func validEmail(s string) bool {
	a, e := mail.ParseAddress(s)
	return e == nil && a.Address == s && len(s) <= 254
}
func (a *app) register(w http.ResponseWriter, r *http.Request) {
	var b credentials
	if decode(r, &b) != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	b.Email = strings.ToLower(strings.TrimSpace(b.Email))
	if !validEmail(b.Email) || len(b.Password) < 12 || len(b.Password) > 256 {
		fail(w, 400, "valid email and 12-256 character password required")
		return
	}
	h, e := a.hash(r.Context(), b.Password)
	if e != nil {
		fail(w, 503, "hash unavailable")
		return
	}
	id, e := security.Random(18)
	if e != nil {
		fail(w, 500, "random source unavailable")
		return
	}
	tag, e := a.db.Exec(r.Context(), "INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,'Viewer') ON CONFLICT(email) DO NOTHING", id, b.Email, h)
	if e != nil {
		fail(w, 500, "registration failed")
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 409, "account unavailable")
		return
	}
	reply(w, 201, map[string]string{"role": "Viewer"})
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var b credentials
	if decode(r, &b) != nil || len(b.Password) > 256 {
		fail(w, 400, "invalid credentials")
		return
	}
	b.Email = strings.ToLower(strings.TrimSpace(b.Email))
	var id, h string
	var secret *string
	var last int64
	e := a.db.QueryRow(r.Context(), "SELECT id,password_hash,totp_secret,totp_last FROM users WHERE email=$1", b.Email).Scan(&id, &h, &secret, &last)
	if errors.Is(e, pgx.ErrNoRows) {
		_, _ = a.hash(r.Context(), b.Password)
		fail(w, 401, "invalid credentials")
		return
	}
	if e != nil {
		fail(w, 503, "account store unavailable")
		return
	}
	if !a.verify(r.Context(), b.Password, h) {
		fail(w, 401, "invalid credentials")
		return
	}
	if secret != nil {
		if b.Code == "" {
			fail(w, 401, "MFA code required")
			return
		}
		s, e := a.unseal(*secret)
		if e != nil {
			fail(w, 500, "MFA unavailable")
			return
		}
		step, ok := matchTOTP(b.Code, s, time.Now())
		if !ok || step <= last {
			fail(w, 401, "invalid or reused MFA code")
			return
		}
		tag, e := a.db.Exec(r.Context(), "UPDATE users SET totp_last=$1 WHERE id=$2 AND totp_last<$1 AND totp_secret=$3", step, id, *secret)
		if e != nil || tag.RowsAffected() != 1 {
			fail(w, 401, "MFA verification failed")
			return
		}
	}
	access, refresh, e := a.newSession(r.Context(), id)
	if e != nil {
		fail(w, 503, "session creation failed")
		return
	}
	a.cookies(w, access, refresh, sessionTTL)
	reply(w, 200, map[string]bool{"ok": true})
}
func matchTOTP(code, secret string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	for _, offset := range []int{0, -1, 1} {
		t := now.Add(time.Duration(offset) * 30 * time.Second)
		ok, e := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e == nil && ok {
			return t.Unix() / 30, true
		}
	}
	return 0, false
}
func (a *app) mfaSetup(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	var b struct {
		Password string `json:"password"`
	}
	if decode(r, &b) != nil {
		fail(w, 400, "password required")
		return
	}
	var email, h string
	var enabled bool
	if e := a.db.QueryRow(r.Context(), "SELECT email,password_hash,totp_secret IS NOT NULL FROM users WHERE id=$1", p.ID).Scan(&email, &h, &enabled); e != nil || !a.verify(r.Context(), b.Password, h) {
		fail(w, 401, "password verification failed")
		return
	}
	if enabled {
		fail(w, 409, "MFA is already enabled")
		return
	}
	k, e := totp.Generate(totp.GenerateOpts{Issuer: "Aegis", AccountName: email})
	if e != nil {
		fail(w, 500, "MFA setup failed")
		return
	}
	sealed, e := a.seal(k.Secret())
	if e != nil {
		fail(w, 500, "MFA setup failed")
		return
	}
	tag, e := a.db.Exec(r.Context(), "UPDATE users SET totp_pending=$1 WHERE id=$2 AND totp_secret IS NULL", sealed, p.ID)
	if e != nil || tag.RowsAffected() != 1 {
		fail(w, 409, "MFA setup failed")
		return
	}
	reply(w, 200, map[string]string{"secret": k.Secret(), "uri": k.URL()})
}
func (a *app) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	var b struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if decode(r, &b) != nil {
		fail(w, 400, "code and password required")
		return
	}
	var pending *string
	var h string
	if e := a.db.QueryRow(r.Context(), "SELECT totp_pending,password_hash FROM users WHERE id=$1 AND totp_secret IS NULL", p.ID).Scan(&pending, &h); e != nil || pending == nil || !a.verify(r.Context(), b.Password, h) {
		fail(w, 401, "setup or password invalid")
		return
	}
	s, e := a.unseal(*pending)
	if e != nil {
		fail(w, 500, "MFA unavailable")
		return
	}
	step, ok := matchTOTP(b.Code, s, time.Now())
	if !ok {
		fail(w, 400, "invalid code")
		return
	}
	tag, e := a.db.Exec(r.Context(), "UPDATE users SET totp_secret=totp_pending,totp_pending=NULL,totp_last=$1 WHERE id=$2 AND totp_pending=$3 AND totp_secret IS NULL", step, p.ID, *pending)
	if e != nil || tag.RowsAffected() != 1 {
		fail(w, 409, "MFA confirmation failed")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
