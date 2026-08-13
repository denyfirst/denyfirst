package httpapi

import (
	"net"
	"sync"
)

// DefaultMaxConnections is how many connections may be open at once.
//
// Generous for a site whose entire page is a few kilobytes, and far below
// what it takes to exhaust the machine.
const DefaultMaxConnections = 512

// LimitListener caps how many connections are open at one time.
//
// The limits elsewhere in this package apply to requests, which is too late
// for one attack. A TLS handshake costs an elliptic curve operation before a
// single byte of HTTP arrives, so a client that opens connections, completes
// handshakes and then does nothing never reaches the request path at all. It
// spends the server's processor and holds a file descriptor, and every guard
// written for requests watches it happen.
//
// ReadHeaderTimeout closes each of those connections after five seconds,
// which bounds how long one lasts but not how many arrive. This bounds how
// many.
//
// Go's standard library has no such listener; golang.org/x/net/netutil does,
// and this project has no dependencies, so it is forty lines here instead.
//
// A connection over the cap is accepted and closed immediately rather than
// left queued. Queueing would turn a flood into a slow-motion version of the
// same problem, with legitimate clients waiting behind it.
func LimitListener(inner net.Listener, limit int) net.Listener {
	if limit <= 0 {
		limit = DefaultMaxConnections
	}
	return &limitListener{
		Listener: inner,
		slots:    make(chan struct{}, limit),
	}
}

type limitListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	// A loop rather than a recursive call.
	//
	// The recursive form reads more neatly and is wrong under exactly the
	// conditions this listener exists for: a flood arriving faster than
	// connections close means one refusal after another, and Go does not
	// optimise a tail call, so each refusal adds a stack frame. The loop
	// refuses as many as arrive in constant space.
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: l.release}, nil
		default:
			// At the cap. Closing at once tells the client to go away, which
			// is a better answer than a connection that hangs and a user who
			// waits. The listener keeps running: refusing one connection must
			// not stop the server taking the next.
			_ = conn.Close()
		}
	}
}

func (l *limitListener) release() {
	select {
	case <-l.slots:
	default:
		// Unreachable unless a connection is closed twice, which the sync.Once
		// below prevents. Draining defensively rather than blocking is the
		// safer failure: a leaked slot costs capacity, a blocked release
		// costs the listener.
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	// http.Server can close a connection more than once. Releasing the slot
	// twice would let the cap drift upwards over the life of the process.
	c.once.Do(c.release)
	return err
}
