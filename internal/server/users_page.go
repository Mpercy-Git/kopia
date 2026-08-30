package server

import (
	"bytes"
	_ "embed"
	"net/http"

	"github.com/kopia/kopia/internal/clock"
)

// UsersPagePath is the path of the built-in page for managing repository user accounts.
const UsersPagePath = "/users"

//go:embed users.html
var usersPageHTML []byte

// serveUsersPage serves the built-in page for managing repository user accounts. The page is
// served by the server itself instead of the HTML UI bundle, so that user accounts can be
// managed without running CLI commands on the machine hosting the repository server.
func (s *Server) serveUsersPage(w http.ResponseWriter, r *http.Request) {
	rc := s.captureRequestContext(w, r)

	//nolint:contextcheck
	if !s.isAuthenticated(rc) {
		return
	}

	if !requireUIUser(r.Context(), rc) {
		http.Error(w, "UI Access denied.", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	http.ServeContent(w, r, "users.html", clock.Now(),
		bytes.NewReader(s.patchIndexBytes(s.ensureSessionID(w, r), usersPageHTML)))
}
