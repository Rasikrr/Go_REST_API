package main

import (
	"go_sql/config"
	"go_sql/emailverif"
	"log"
)

func main() {
	cfg := config.MustLoad()
	store, err := NewPostgresStore(cfg.Storage)
	if err != nil {
		log.Fatal(err)
	}
	emailSender, err := emailverif.NewGmailSender(cfg.EmailServer)
	if err != nil {
		panic(err)
	}
	if err = store.Init(); err != nil {
		log.Fatal(err)
	}
	server := NewAPIServer(cfg.HttpServer, store, emailSender)
	server.Run()

}

// TODO async email sending
// TODO data validation
// TODO email with verification link
