package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"syscall"

	"github.com/docker/docker/daemon/logger"
)

type startLoggingRequest struct {
	File string
}

type capabilitiesResponse struct {
	Cap logger.Capability
}

type driver struct {
	mu   sync.Mutex
	logs map[string]io.Closer
}

type stopLoggingRequest struct {
	File string
}

func handle(mux *http.ServeMux) {
	d := &driver{logs: make(map[string]io.Closer)}
	mux.HandleFunc("/LogDriver.StartLogging", func(w http.ResponseWriter, r *http.Request) {
		var req startLoggingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f, err := os.OpenFile(req.File, syscall.O_RDONLY, 0700)
		if err != nil {
			respond(err, w)
		}

		d.mu.Lock()
		d.logs[req.File] = f
		d.mu.Unlock()

		go io.Copy(ioutil.Discard, f)
		respond(err, w)
	})

	mux.HandleFunc("/LogDriver.StopLogging", func(w http.ResponseWriter, r *http.Request) {
		var req stopLoggingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		d.mu.Lock()
		if f := d.logs[req.File]; f != nil {
			f.Close()
		}
		d.mu.Unlock()
		respond(nil, w)
	})

	mux.HandleFunc("/LogDriver.Capabilities", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&capabilitiesResponse{})
	})
}

type response struct {
	Err string
}

func respond(err error, w io.Writer) {
	var res response
	if err != nil {
		res.Err = err.Error()
	}
	json.NewEncoder(w).Encode(&res)
}
