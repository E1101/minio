/*
 * Minio Cloud Storage, (C) 2016 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync/atomic"
)

// Current number of concurrent http requests
var globalInShutdown int32

// Server - the main mux server
type Server struct {
	*http.Server
}

// NewServer constructor to create a Server
func NewServer(addr string, handler http.Handler) *Server {
	m := &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: handler,
			TLSConfig: &tls.Config{
				// Causes servers to use Go's default ciphersuite preferences,
				// which are tuned to avoid attacks. Does nothing on clients.
				PreferServerCipherSuites: true,
				// Set minimum version to TLS 1.2
				MinVersion: tls.VersionTLS12,
			}, // Always instantiate.
		},
	}

	// Returns configured HTTP server.
	return m
}

type connRequestHandler struct {
	handler http.Handler
}

func setConnRequestHandler(h http.Handler) http.Handler {
	return connRequestHandler{handler: h}
}

func (c connRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&globalInShutdown) == 1 {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	c.handler.ServeHTTP(w, r)
}

// ListenAndServe - serve HTTP requests with protocol multiplexing support
// TLS is actived when certFile and keyFile parameters are not empty.
func (m *Server) ListenAndServe() (err error) {
	go handleServiceSignals()

	certFile, keyFile := getPublicCertFile(), getPrivateKeyFile()
	if globalIsSSL {
		return m.ListenAndServeTLS(certFile, keyFile)
	}

	return m.Server.ListenAndServe()
}

// Shutdown initiates a graceful shutdown.
func (m *Server) Shutdown(ctx context.Context) error {
	atomic.AddInt32(&globalInShutdown, 1)
	defer atomic.AddInt32(&globalInShutdown, -1)

	return m.Server.Shutdown(ctx)
}
