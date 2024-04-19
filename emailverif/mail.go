package emailverif

import (
	"fmt"
	"github.com/jordan-wright/email"
	"go_sql/config"
	"net/smtp"
)

const (
	smtpAuthAddress   = "smtp.gmail.com"
	smtpServerAddress = "smtp.gmail.com:587"
)

type EmailSender interface {
	SendEmail(
		subject string,
		content string,
		to []string,
		cc []string,
		bcc []string,
		attachFiles []string,
	) error
}

type GmailSender struct {
	name              string
	fromEmailAddress  string
	fromEmailPassword string
}

func NewGmailSender(cfg *config.EmailServer) (*GmailSender, error) {
	sender := &GmailSender{
		name:              cfg.Name,
		fromEmailAddress:  cfg.Addr,
		fromEmailPassword: cfg.Password,
	}
	err := sender.ping()
	return sender, err
}

func (sender *GmailSender) ping() error {
	return sender.SendEmail("test",
		"<h1>Works!</h1>",
		[]string{"rs.t.95@mail.ru"},
		[]string{},
		[]string{},
		[]string{},
	)
}

func (sender *GmailSender) SendEmail(
	subject string,
	content string,
	to []string,
	cc []string,
	bcc []string,
	attachFiles []string,
) error {
	e := email.NewEmail()
	e.From = fmt.Sprintf("%s <%s>", sender.name, sender.fromEmailAddress)
	e.Subject = subject
	e.HTML = []byte(content)
	e.To = to
	e.Cc = cc
	e.Bcc = bcc
	for _, f := range attachFiles {
		_, err := e.AttachFile(f)
		if err != nil {
			return fmt.Errorf("failed to attach file %s: %w", f, err)
		}
	}
	plainAuth := smtp.PlainAuth("", sender.fromEmailAddress, sender.fromEmailPassword, smtpAuthAddress)
	return e.Send(smtpServerAddress, plainAuth)
}
