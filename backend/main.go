package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-project/aegis/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
)

//go:embed migrations/*.sql
var migrations embed.FS

type app struct {
	db              *pgxpool.Pool
	rdb             *redis.Client
	jwtKey, mfaKey  []byte
	origin, proxyIP string
	allowed         map[string]bool
	audit           chan auditEvent
	hashSlots       chan struct{}
}
type auditEvent struct{ Rule, Method string }
type principal struct{ ID, Role, Family string }
type contextKey struct{}

func who(r *http.Request) principal { p, _ := r.Context().Value(contextKey{}).(principal); return p }
func env(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing %s", k)
	}
	return v
}
func key(k string) []byte {
	b, e := hex.DecodeString(env(k))
	if e != nil || len(b) != 32 {
		log.Fatalf("%s must contain 64 hex characters", k)
	}
	return b
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, e := pgxpool.New(ctx, env("DATABASE_URL"))
	if e != nil {
		log.Fatal(e)
	}
	defer db.Close()
	opt, e := redis.ParseURL(env("REDIS_URL"))
	if e != nil {
		log.Fatal(e)
	}
	opt.MaxRetries = -1
	rd := redis.NewClient(opt)
	defer rd.Close()
	a := &app{db: db, rdb: rd, jwtKey: key("JWT_SECRET"), mfaKey: key("MFA_SECRET"), origin: env("PUBLIC_ORIGIN"), proxyIP: os.Getenv("TRUSTED_PROXY_IP"), allowed: map[string]bool{"demo.aegis.test": true}, audit: make(chan auditEvent, 512), hashSlots: make(chan struct{}, 2)}
	for _, h := range strings.Split(os.Getenv("RECON_ALLOWED_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			a.allowed[h] = true
		}
	}
	startup, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if e = db.Ping(startup); e != nil {
		log.Fatal(e)
	}
	if e = rd.Ping(startup).Err(); e != nil {
		log.Fatal(e)
	}
	if e = a.migrate(startup); e != nil {
		log.Fatal(e)
	}
	if e = a.bootstrap(startup); e != nil {
		log.Fatal(e)
	}
	go a.auditWorker(ctx)
	for i := 0; i < 2; i++ {
		go a.scanWorker(ctx)
	}
	r := chi.NewRouter()
	r.Get("/health", a.health)
	r.Route("/api", func(r chi.Router) {
		r.Use(a.edge)
		r.Get("/probe", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]any{"ok": true}) })
		r.Group(func(r chi.Router) {
			r.Use(a.authRate)
			r.Post("/auth/register", a.register)
			r.Post("/auth/login", a.login)
			r.Post("/auth/refresh", a.refresh)
			r.Post("/auth/logout", a.logout)
		})
		r.Post("/vault/{id}/consume", a.vaultConsume)
		r.Group(func(r chi.Router) {
			r.Use(a.authenticate)
			r.Get("/me", a.me)
			r.Post("/mfa/setup", a.mfaSetup)
			r.Post("/mfa/confirm", a.mfaConfirm)
			r.Get("/scans", a.scanList)
			r.Post("/scans", a.scanCreate)
			r.Get("/scans/{id}", a.scanGet)
			r.Get("/scans/{id}/events", a.scanEvents)
			r.Get("/telemetry", a.telemetry)
			r.Post("/vault", a.vaultCreate)
			r.Get("/admin/users", a.users)
			r.Put("/admin/users/{id}/role", a.changeRole)
		})
	})
	srv := &http.Server{Addr: ":8080", Handler: r, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 150 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = srv.Shutdown(c)
	}()
	log.Print("Aegis API listening on :8080")
	if e = srv.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
		log.Fatal(e)
	}
}
func (a *app) migrate(ctx context.Context) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(736123)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY)"); e != nil {
		return e
	}
	files, e := migrations.ReadDir("migrations")
	if e != nil {
		return e
	}
	for _, f := range files {
		var found bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)", f.Name()).Scan(&found); e != nil {
			return e
		}
		if found {
			continue
		}
		b, e := migrations.ReadFile("migrations/" + f.Name())
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, string(b), pgx.QueryExecModeSimpleProtocol); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO schema_migrations VALUES($1)", f.Name()); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (a *app) health(w http.ResponseWriter, r *http.Request) {
	ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
	defer c()
	if a.db.Ping(ctx) != nil || a.rdb.Ping(ctx).Err() != nil {
		fail(w, 503, "dependencies unavailable")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func (a *app) hash(ctx context.Context, p string) (string, error) {
	select {
	case a.hashSlots <- struct{}{}:
		defer func() { <-a.hashSlots }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	h := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(h), nil
}
func (a *app) verify(ctx context.Context, p, stored string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 2 || len(p) > 256 {
		return false
	}
	salt, e := hex.DecodeString(parts[0])
	if e != nil || len(salt) != 16 {
		return false
	}
	h, e := hex.DecodeString(parts[1])
	if e != nil || len(h) != 32 {
		return false
	}
	select {
	case a.hashSlots <- struct{}{}:
		defer func() { <-a.hashSlots }()
	case <-ctx.Done():
		return false
	}
	return subtle.ConstantTimeCompare(h, argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)) == 1
}
func (a *app) seal(s string) (string, error) {
	b, e := aes.NewCipher(a.mfaKey)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(g.Seal(n, n, []byte(s), nil)), nil
}
func (a *app) unseal(s string) (string, error) {
	raw, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return "", e
	}
	b, e := aes.NewCipher(a.mfaKey)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil || len(raw) < g.NonceSize() {
		return "", errors.New("invalid encrypted MFA secret")
	}
	p, e := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	return string(p), e
}
func (a *app) bootstrap(ctx context.Context) error {
	email := strings.ToLower(strings.TrimSpace(env("ADMIN_EMAIL")))
	password := env("ADMIN_PASSWORD")
	if len(password) < 16 || len(password) > 256 {
		return errors.New("ADMIN_PASSWORD must be 16-256 characters")
	}
	var role string
	e := a.db.QueryRow(ctx, "SELECT role FROM users WHERE email=$1", email).Scan(&role)
	if e == nil {
		if role != "Admin" {
			return errors.New("bootstrap email belongs to non-admin")
		}
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	id, e := security.Random(18)
	if e != nil {
		return e
	}
	h, e := a.hash(ctx, password)
	if e != nil {
		return e
	}
	_, e = a.db.Exec(ctx, "INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,'Admin')", id, email, h)
	return e
}
func (a *app) access(id, family string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": id, "sid": family, "iss": "aegis", "aud": "aegis-api", "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix()}).SignedString(a.jwtKey)
}
func (a *app) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("aegis_access")
		if e != nil {
			fail(w, 401, "sign in required")
			return
		}
		t, e := jwt.Parse(c.Value, func(t *jwt.Token) (any, error) { return a.jwtKey, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("aegis"), jwt.WithAudience("aegis-api"), jwt.WithExpirationRequired())
		if e != nil || !t.Valid {
			fail(w, 401, "session expired")
			return
		}
		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			fail(w, 401, "invalid session")
			return
		}
		id, _ := claims.GetSubject()
		family, _ := claims["sid"].(string)
		if id == "" || family == "" {
			fail(w, 401, "invalid session")
			return
		}
		state, e := a.rdb.HGetAll(r.Context(), "session:"+family).Result()
		if e != nil {
			fail(w, 503, "session store unavailable")
			return
		}
		if state["uid"] != id || state["revoked"] == "1" {
			fail(w, 401, "session revoked")
			return
		}
		var role string
		e = a.db.QueryRow(r.Context(), "SELECT role FROM users WHERE id=$1", id).Scan(&role)
		if e != nil {
			fail(w, 401, "account unavailable")
			return
		}
		if !a.limit(w, r, "user:"+id, 120) {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, principal{id, role, family})))
	})
}
func (a *app) me(w http.ResponseWriter, r *http.Request) {
	var email string
	var mfa bool
	p := who(r)
	if e := a.db.QueryRow(r.Context(), "SELECT email,totp_secret IS NOT NULL FROM users WHERE id=$1", p.ID).Scan(&email, &mfa); e != nil {
		fail(w, 500, "account unavailable")
		return
	}
	reply(w, 200, map[string]any{"id": p.ID, "email": email, "role": p.Role, "mfa": mfa})
}
func (a *app) users(w http.ResponseWriter, r *http.Request) {
	if who(r).Role != "Admin" {
		fail(w, 403, "admin required")
		return
	}
	rows, e := a.db.Query(r.Context(), "SELECT id,email,role FROM users ORDER BY created_at LIMIT 100")
	if e != nil {
		fail(w, 500, "database unavailable")
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var id, email, role string
		if e = rows.Scan(&id, &email, &role); e != nil {
			fail(w, 500, "database error")
			return
		}
		out = append(out, map[string]string{"id": id, "email": email, "role": role})
	}
	if rows.Err() != nil {
		fail(w, 500, "database error")
		return
	}
	reply(w, 200, out)
}
func (a *app) changeRole(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	id := chi.URLParam(r, "id")
	if p.Role != "Admin" || p.ID == id {
		fail(w, 403, "cannot change this role")
		return
	}
	var b struct {
		Role string `json:"role"`
	}
	if decode(r, &b) != nil || (b.Role != "Admin" && b.Role != "Analyst" && b.Role != "Viewer") {
		fail(w, 400, "invalid role")
		return
	}
	tag, e := a.db.Exec(r.Context(), "UPDATE users SET role=$1 WHERE id=$2", b.Role, id)
	if e != nil {
		fail(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "user not found")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func number(v int64) string        { return strconv.FormatInt(v, 10) }
func wrap(e error, s string) error { return fmt.Errorf("%s: %w", s, e) }
