//go:build diag

package monitor

// Renders the monitoring page from a real database, so the result can be
// looked at rather than only asserted on. Behind the `diag` build tag, like
// the other tests that read live data: excluded from `make check` (which
// must run with no secret and no live state) while CI still type-checks it.
//
//	MONITOR_DIAG_DB=<copy of brokerd.db> \
//	  go test ./internal/monitor/ -tags diag -run TestDiagRenderPage -v
//
// Use a copy (`sqlite3 <db> ".backup <copy>"`), never the live file.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

func TestDiagRenderPage(t *testing.T) {
	dbPath := os.Getenv("MONITOR_DIAG_DB")
	if dbPath == "" {
		t.Skip("MONITOR_DIAG_DB not set")
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open(%s): %v", dbPath, err)
	}
	defer func() { _ = store.Close() }()

	boards := []config.Board{}
	for _, id := range strings.Split(os.Getenv("MONITOR_DIAG_BOARDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			boards = append(boards, config.Board{ID: id, Username: id})
		}
	}

	s := New(Options{
		ListenAddr: "127.0.0.1:0",
		APIToken:   "diag-token",
		Store:      store,
		AuthHook:   auth.New(map[string]string{}, 5, 30*time.Minute, nil),
		Boards:     boards,
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer diag-token")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	body := w.Body.String()

	out := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(out, []byte(body), 0o600); err != nil {
		t.Fatalf("writing rendered page: %v", err)
	}
	t.Logf("rendered %d bytes to %s", len(body), out)

	// Report what each section actually produced, so an empty section is
	// visible rather than assumed.
	rowCount := regexp.MustCompile(`(?s)<tr>`).FindAllString(body, -1)
	t.Logf("table rows: %d", len(rowCount))
	for _, marker := range []string{
		"no frames stored yet", "no messages stored", "nothing stored yet",
		"No telemetry has arrived", "no boards configured",
	} {
		if strings.Contains(body, marker) {
			t.Logf("empty-state shown: %q", marker)
		}
	}
	if strings.Contains(body, "diag-token") {
		t.Error("the page contains the token used to open it")
	}
}
