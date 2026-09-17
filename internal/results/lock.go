package results

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// One writer at a time per history file.
//
// Put appends and then trims, which is a read and a rewrite. Two writers
// interleaving those — two scans of one host finishing together in porchd, or
// porchd and porch-scan sharing a directory — could each read the file, each
// drop the other's line, and leave a history missing a scan or holding half of
// one. The 2026-09-16 audit (A24) found nothing serialising them.
//
// Two locks, because they cover different cases. A mutex per path covers the
// goroutines of one process, cheaply and exactly. A lock file beside the
// history covers processes, portably: the standard library has no advisory
// lock that works the same on every platform this ships for, and O_EXCL does.

var (
	// lockWait bounds how long a writer waits for another. A scan's result is
	// worth a short wait and not a stuck request.
	lockWait = 3 * time.Second

	// lockStale is how old a lock file has to be before it is taken as left
	// behind by a process that died holding it. A write takes milliseconds.
	lockStale = 30 * time.Second

	lockPoll = 15 * time.Millisecond

	// maxRead bounds how much of one history is read back. Keep is the
	// operator's and unset keeps everything, so a history can outgrow what a
	// reader should load; past this only the newest part is read, and the
	// oldest records are the ones not shown. Not a retention period: nothing
	// is deleted.
	maxRead int64 = 16 << 20
)

var (
	pathLocksMu sync.Mutex
	pathLocks   = map[string]*sync.Mutex{}
)

// errLocked means another writer held the history for longer than lockWait.
var errLocked = errors.New("results: another writer is holding this history")

// pathLock is the in-process mutex for one history.
func pathLock(path string) *sync.Mutex {
	pathLocksMu.Lock()
	defer pathLocksMu.Unlock()
	mu, ok := pathLocks[path]
	if !ok {
		mu = &sync.Mutex{}
		pathLocks[path] = mu
	}
	return mu
}

// readLock takes the in-process lock alone. A read writes nothing to disk,
// not even a lock file: porch-scan -history is an operator reading their own
// notes, possibly from a directory mounted read-only.
func readLock(path string) func() {
	mu := pathLock(path)
	mu.Lock()
	return mu.Unlock
}

// lock takes both locks for path and returns the function that releases them.
func lock(path string) (func(), error) {
	mu := pathLock(path)
	mu.Lock()

	lockPath := path + ".lock"
	deadline := time.Now().Add(lockWait)
	for {
		// #nosec G304 -- beside a path pathFor built and checked.
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err == nil {
			f.Close() //nolint:errcheck,gosec // the file's existence is the lock
			return func() {
				os.Remove(lockPath) //nolint:errcheck,gosec // a lock left behind goes stale
				mu.Unlock()
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			mu.Unlock()
			return nil, err
		}

		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > lockStale {
			os.Remove(lockPath) //nolint:errcheck,gosec // another writer may have removed it first
			continue
		}
		if time.Now().After(deadline) {
			mu.Unlock()
			return nil, errLocked
		}
		time.Sleep(lockPoll)
	}
}

// replace writes body to path through a file beside it and a rename, so a
// reader sees the old history or the new one and never half of either.
func replace(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trim-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) //nolint:errcheck // gone after a successful rename

	if err := tmp.Chmod(fileMode); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		// Windows keeps no Unix mode; CreateTemp already made the file its
		// owner's alone there.
		tmp.Close() //nolint:errcheck,gosec // the chmod error is the one worth reporting
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close() //nolint:errcheck,gosec // the write error is the one worth reporting
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Windows refuses to rename over a file another process has open — a
	// person reading the history in an editor. A short retry covers a reader
	// that is about to finish; past it the history is rewritten in place.
	// Still whole to every reader in this process, which takes the same lock,
	// and the alternative is a record lost to somebody reading a file.
	for try := 0; ; try++ {
		err = os.Rename(name, path)
		if err == nil {
			return nil
		}
		if try == renameTries {
			break
		}
		time.Sleep(lockPoll)
	}
	// #nosec G304 -- a path pathFor built and checked.
	return os.WriteFile(path, body, fileMode)
}

// renameTries bounds the wait for a reader holding the file open.
const renameTries = 10

// readTail reads a history, or its newest maxRead bytes.
func readTail(path string) ([]byte, error) {
	// #nosec G304 -- a path pathFor built and checked.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	cut := info.Size() > maxRead
	if cut {
		if _, err := f.Seek(info.Size()-maxRead, io.SeekStart); err != nil {
			return nil, err
		}
	}
	body, err := io.ReadAll(io.LimitReader(f, maxRead))
	if err != nil || !cut {
		return body, err
	}
	// The first line was entered part way. The rest of it is not read as a
	// record, whatever it happens to look like.
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		return body[i+1:], nil
	}
	return nil, nil
}
