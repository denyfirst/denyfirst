package vault

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Handler serves the history to somebody already signed in. It is mounted
// only behind internal/access's gate, which is what decides who that is; this
// adds that a deletion must come from the installation's own pages.
//
//	GET    /api/v1/history        the list, newest first
//	GET    /api/v1/history/{id}   one report, as it was kept
//	DELETE /api/v1/history/{id}   that report, removed for good
func (v *Vault) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/history")
		if !ok {
			refuse(w, http.StatusNotFound, "not_found", "There is nothing here.")
			return
		}
		id, one := strings.CutPrefix(rest, "/")
		switch {
		case rest == "" && r.Method == http.MethodGet:
			entries, st, err := v.List()
			if err != nil {
				failed(w, err)
				return
			}
			if entries == nil {
				entries = []Entry{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "status": st})
		case one && r.Method == http.MethodGet:
			rec, err := v.Get(id)
			if err != nil {
				failed(w, err)
				return
			}
			writeJSON(w, http.StatusOK, rec)
		case one && r.Method == http.MethodDelete:
			if !fromThisPage(r) {
				refuse(w, http.StatusForbidden, "cross_site", "Delete reports from this installation's own pages.")
				return
			}
			if err := v.Delete(id); err != nil {
				failed(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, DELETE")
			refuse(w, http.StatusMethodNotAllowed, "method", "Read the history with GET, and delete a report with DELETE.")
		}
	})
}

func failed(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		refuse(w, http.StatusNotFound, "not_found", "There is no such report.")
	case errors.Is(err, ErrLocked):
		refuse(w, http.StatusServiceUnavailable, "locked", "Sign in again to open the history.")
	default:
		// Paths and the system's words stay in this process.
		refuse(w, http.StatusInternalServerError, "unavailable", "The history could not be read.")
	}
}

// fromThisPage refuses a request another site made the browser send.
func fromThisPage(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
		return true
	}
	return false
}

// secure sets the headers the API sets: these answers are JSON, need no
// resource of any kind, and are never cached — a cache would hold the very
// thing the vault exists to keep sealed.
func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func refuse(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]map[string]string{"error": {"code": code, "message": message}})
}
