package issue

import (
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/history"
)

func BenchmarkIssueHistoryWindow5(b *testing.B) {
	store := openIssueBenchmarkStore(b)

	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	passwords := [][]byte{{'a'}, {'b'}, {'c'}, {'d'}, {'e'}}

	for i, password := range passwords {
		record := issueTestHistoryRecord("svc-01", password, byte(10+i*20), now.Add(time.Duration(i)*time.Minute))

		if err := store.Save(record); err != nil {
			b.Fatalf("seed benchmark history: %v", err)
		}
	}

	password := []byte{'a'}

	reused, err := store.Reused("svc-01", password, 5)
	if err != nil {
		b.Fatalf("benchmark setup: check reuse: %v", err)
	}

	if !reused {
		b.Fatal("benchmark setup: password must match history window")
	}

	b.ReportAllocs()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reused, err := store.Reused("svc-01", password, 5)
		if err != nil {
			b.Fatal(err)
		}

		if !reused {
			b.Fatal("benchmark password must match history window")
		}
	}
}

func openIssueBenchmarkStore(b *testing.B) *history.Store {
	b.Helper()

	store, err := history.Open(b.TempDir())
	if err != nil {
		b.Fatalf("open benchmark history store: %v", err)
	}

	b.Cleanup(
		func() {
			if err := store.Close(); err != nil {
				b.Errorf("close benchmark history store: %v", err)
			}
		},
	)

	return store
}
