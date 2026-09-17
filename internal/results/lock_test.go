package results

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Writers finishing together lose nothing and corrupt nothing (audit A24).
func TestConcurrentWritersKeepEveryRecord(t *testing.T) {
	for _, keep := range []int{0, 10} {
		s := &Store{Dir: t.TempDir(), Keep: keep}
		const writers = 60

		var wg sync.WaitGroup
		errs := make(chan error, writers)
		for i := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- s.Put("tls", "example.test", "strong", "porch-tls-v7", []string{fmt.Sprintf("rule.%d", i)})
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("keep %d: a writer failed: %v", keep, err)
			}
		}

		got, err := s.History("tls", "example.test")
		if err != nil {
			t.Fatal(err)
		}
		want := writers
		if keep > 0 {
			want = keep
		}
		if len(got) != want {
			t.Errorf("keep %d: %d records survive %d writers, want %d", keep, len(got), writers, want)
		}
		path, _ := s.pathFor("tls", "example.test")
		body, _ := os.ReadFile(path)
		if lines := strings.Count(string(body), "\n"); lines != want {
			t.Errorf("keep %d: the file holds %d lines, want %d whole ones", keep, lines, want)
		}
		if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("keep %d: a lock was left behind", keep)
		}
	}
}

// A lock another process holds is waited for, and one it left behind is not.
func TestALockIsWaitedForUnlessItIsStale(t *testing.T) {
	previous := lockWait
	lockWait = 100 * time.Millisecond
	t.Cleanup(func() { lockWait = previous })

	s := &Store{Dir: t.TempDir()}
	path, _ := s.pathFor("web", "example.test")
	if err := os.MkdirAll(pathDir(path), dirMode); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path+".lock", nil, fileMode); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("web", "example.test", "weak", "porch-web-v3", nil); !errors.Is(err, errLocked) {
		t.Errorf("a held lock was not waited for: %v", err)
	}
	if got, _ := s.History("web", "example.test"); len(got) != 0 {
		t.Errorf("a write went past a held lock: %v", got)
	}

	old := time.Now().Add(-2 * lockStale)
	if err := os.Chtimes(path+".lock", old, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("web", "example.test", "weak", "porch-web-v3", nil); err != nil {
		t.Errorf("a stale lock stopped a write: %v", err)
	}
}

// A history larger than the read bound is read from its newest end, whole
// records only.
func TestALargeHistoryIsReadFromItsNewestEnd(t *testing.T) {
	previous := maxRead
	maxRead = 400
	t.Cleanup(func() { maxRead = previous })

	s := store(t, 0)
	for i := range 20 {
		if err := s.Put("mail", "example.test", "strong", "porch-mail-v1", []string{fmt.Sprintf("r%02d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.History("mail", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) >= 20 {
		t.Fatalf("%d records read under a %d-byte bound", len(got), maxRead)
	}
	if last := got[len(got)-1].Findings; len(last) != 1 || last[0] != "r19" {
		t.Errorf("the newest record was not read: %v", got[len(got)-1])
	}
	for _, r := range got {
		if r.Check != "mail" || len(r.Findings) != 1 {
			t.Errorf("a cut line was read as a record: %+v", r)
		}
	}
	path, _ := s.pathFor("mail", "example.test")
	if body, _ := os.ReadFile(path); strings.Count(string(body), "\n") != 20 {
		t.Error("reading a large history deleted something")
	}
}

// Trimming leaves nothing beside the history.
func TestTrimmingLeavesNoTemporaryFile(t *testing.T) {
	s := store(t, 2)
	for range 5 {
		if err := s.Put("tls", "example.test", "strong", "porch-tls-v7", nil); err != nil {
			t.Fatal(err)
		}
	}
	path, _ := s.pathFor("tls", "example.test")
	entries, err := os.ReadDir(pathDir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v, want the history alone", names)
	}
}

func pathDir(p string) string { return filepath.Dir(p) }

// A trim replaces the history rather than rewriting it in place, so a reader
// that opened it before the trim reads the history it opened, whole.
func TestATrimReplacesTheHistoryWhole(t *testing.T) {
	s := store(t, 2)
	for range 3 {
		if err := s.Put("tls", "example.test", "strong", "porch-tls-v7", nil); err != nil {
			t.Fatal(err)
		}
	}
	path, _ := s.pathFor("tls", "example.test")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if err := s.Put("tls", "example.test", "weak", "porch-tls-v7", nil); err != nil {
		t.Fatalf("a trim with a reader open failed: %v", err)
	}
	if got, _ := s.History("tls", "example.test"); len(got) != 2 || got[1].Verdict != "weak" {
		t.Errorf("the trim did not land: %+v", got)
	}

	// Windows cannot rename over an open file, so there the history is
	// rewritten in place and this half cannot hold; CI checks it on Linux.
	if runtime.GOOS == "windows" {
		return
	}
	held, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	// The append lands in the file the reader holds; the trim then replaces
	// the name. Rewritten in place, the reader would see the trimmed two lines
	// instead of the untouched two and the appended one.
	if !strings.HasPrefix(string(held), string(before)) || strings.Count(string(held), "\n") != 3 {
		t.Errorf("a reader open across a trim saw the file rewritten under it:\n%q\nwas\n%q", held, before)
	}
}

// Reading writes nothing, not even a lock.
func TestReadingAHistoryWritesNothing(t *testing.T) {
	s := store(t, 0)
	if got, err := s.History("tls", "never.test"); err != nil || got != nil {
		t.Errorf("a name never scanned: %v, %v", got, err)
	}
	if err := s.Put("tls", "once.test", "strong", "porch-tls-v7", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.History("tls", "once.test"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "tls"))
	if len(entries) != 1 {
		t.Errorf("reading left %d entries beside one history", len(entries))
	}
}

// A read does not wait for another process's writer: it takes no lock file.
func TestAReadDoesNotWaitForAnotherProcess(t *testing.T) {
	previous := lockWait
	lockWait = time.Second
	t.Cleanup(func() { lockWait = previous })

	s := store(t, 0)
	if err := s.Put("web", "held.test", "strong", "porch-web-v3", nil); err != nil {
		t.Fatal(err)
	}
	path, _ := s.pathFor("web", "held.test")
	if err := os.WriteFile(path+".lock", nil, fileMode); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	got, err := s.History("web", "held.test")
	if err != nil || len(got) != 1 {
		t.Errorf("a read beside another process's lock: %v, %v", got, err)
	}
	if waited := time.Since(start); waited > lockWait/2 {
		t.Errorf("a read waited %v for a lock file it should not take", waited)
	}
}
