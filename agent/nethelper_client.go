package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"
)

func newByteReader(value []byte) *bytes.Reader {
	return bytes.NewReader(value)
}

func callNetHelper(ctx context.Context, socketPath string, request []byte) ([]byte, error) {
	if socketPath != "/run/vps-guardian-net-helper/helper.sock" {
		return nil, errors.New("port traffic helper socket is not approved")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, errors.New("port traffic helper is unavailable")
	}
	defer connection.Close()
	deadline := time.Now().Add(20 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, errors.New("port traffic helper deadline failed")
	}
	if len(request) == 0 || len(request) > 16*1024 {
		return nil, errors.New("port traffic helper request exceeds limit")
	}
	if _, err := connection.Write(request); err != nil {
		return nil, errors.New("port traffic helper request failed")
	}
	if unix, ok := connection.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	response, err := io.ReadAll(io.LimitReader(connection, 256*1024+1))
	if err != nil || len(response) > 256*1024 {
		return nil, errors.New("port traffic helper response failed")
	}
	return response, nil
}
