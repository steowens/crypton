package messaging

import (
	"bytes"
	"io"
	"time"

	mail "github.com/emersion/go-message/mail"
	log "github.com/sirupsen/logrus"
)

func exampleWriter() string {
	var b bytes.Buffer

	from := []*mail.Address{{Name: "Mitsuha Miyamizu", Address: "mitsuha.miyamizu@example.org"}}
	to := []*mail.Address{{Name: "Taki Tachibana", Address: "taki.tachibana@example.org"}}

	// Create our mail header
	var h mail.Header
	h.SetDate(time.Now())
	h.SetAddressList("From", from)
	h.SetAddressList("To", to)

	// Create a new mail writer
	mw, err := mail.CreateWriter(&b, h)
	if err != nil {
		log.Fatal(err)
	}
	defer mw.Close()

	// Create a text part
	tw, err := mw.CreateInline()
	if err != nil {
		log.Error(err)
		return ""
	}
	defer tw.Close()

	var th mail.InlineHeader
	th.Set("Content-Type", "text/plain")
	w, err := tw.CreatePart(th)
	if err != nil {
		log.Error(err)
		return ""
	}
	io.WriteString(w, "Who are you?")
	defer w.Close()

	// Create an attachment
	var ah mail.AttachmentHeader
	ah.Set("Content-Type", "image/jpeg")
	ah.SetFilename("picture.jpg")
	aw, err := mw.CreateAttachment(ah)
	if err != nil {
		log.Error(err)
		return ""
	}
	// TODO: write a JPEG file to w
	aw.Close()
	return b.String()
}
