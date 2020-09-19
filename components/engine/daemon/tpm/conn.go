package tpm

import (
	"io"
	"strconv"
	"sync"

	"github.com/google/go-tpm/tpmutil"
)

type conn struct {
	sync.Mutex
	rwc  *io.ReadWriteCloser
	path string
}

func (conn *conn) close() error {
	conn.Lock()
	defer conn.Unlock()
	if conn.rwc != nil {
		rwc := *conn.rwc
		rwc.Close()
	}
	conn.rwc = nil
	return nil
}

// Key returns the key information for the key with the specified keygrip
func (conn *conn) key(handle string, password string) (*key, error) {
	h, err := strconv.ParseUint(handle, 0, 32)
	if err != nil {
		return nil, err
	}

	key := &key{conn: conn, password: password}

	keyHandle := tpmutil.Handle(h)
	err = key.readPublic(keyHandle)
	if err != nil {
		return nil, err
	}
	key.handle = keyHandle

	return key, nil
}
