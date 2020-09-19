package tpm

import "github.com/google/go-tpm/tpm2"

func (conn *conn) open() error {
	conn.Lock()
	defer conn.Unlock()
	rwc, err := tpm2.OpenTPM(conn.path)
	if err != nil {
		return err
	}
	conn.rwc = &rwc
	return nil
}
