package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/aegis-project/aegis/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"net/http"
	"time"
)

type vaultEnvelope struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
	TTL        string `json:"ttl"`
}

func (a *app) vaultCreate(w http.ResponseWriter, r *http.Request) {
	var b vaultEnvelope
	if decode(r, &b) != nil {
		fail(w, 400, "invalid envelope")
		return
	}
	ttl, ok := map[string]time.Duration{"5m": 5 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour}[b.TTL]
	iv, e := base64.RawURLEncoding.DecodeString(b.IV)
	ct, e2 := base64.RawURLEncoding.DecodeString(b.Ciphertext)
	if !ok || e != nil || e2 != nil || len(iv) != 12 || len(ct) < 16 || len(ct) > 64<<10 {
		fail(w, 400, "invalid ciphertext, IV or TTL")
		return
	}
	id, e := security.Random(24)
	if e != nil {
		fail(w, 500, "random source unavailable")
		return
	}
	raw, e := json.Marshal(b)
	if e != nil {
		fail(w, 500, "encoding failed")
		return
	}
	if ok, e := a.rdb.SetNX(r.Context(), "vault:"+id, raw, ttl).Result(); e != nil || !ok {
		fail(w, 503, "vault unavailable")
		return
	}
	reply(w, 201, map[string]string{"id": id})
}
func (a *app) vaultConsume(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rawID, e := base64.RawURLEncoding.DecodeString(id)
	if e != nil || len(rawID) != 24 {
		fail(w, 404, "secret unavailable")
		return
	}
	raw, e := a.rdb.GetDel(r.Context(), "vault:"+id).Bytes()
	if e == redis.Nil {
		fail(w, 404, "secret expired or already consumed")
		return
	}
	if e != nil {
		fail(w, 503, "vault unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
