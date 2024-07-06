package main

import (
	"log"
)

var (
	version  = "master"
	revision = "dev"
)

func main() {
	log.SetFlags(log.Flags() | log.LUTC)
	if len(revision) > 8 {
		revision = revision[:8]
	}
	log.Printf("Cloud IAP Auth & Proxy Server (build: %s.%s)\n", version, revision)

	srv, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
