package main

import (
	"go_sql/config"
	"log"
)

func main() {
	cfg := config.MustLoad()
	store, err := NewPostgresStore(cfg.Storage)
	if err != nil {
		log.Fatal(err)
	}
	if err = store.Init(); err != nil {
		log.Fatal(err)
	}
	server := NewAPIServer(cfg.HttpServer, store)
	server.Run()

}

// do Transfer
// do /logout
// do update account
