package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

var addr = "127.0.0.1:1025"

func init() {
	flag.StringVar(&addr, "l", addr, "Listen address")
}

type backend struct{}

func (bkd *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{}, nil
}

type session struct {
	user string
	auth string
}

func (s *session) AuthPlain(username, password string) error {
	// fmt.Printf("Auth %s %s\n", username, password)
	return nil
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	// fmt.Printf("Mail %s %+v\n", from, opts)
	return nil
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// fmt.Printf("Rcpt %s %+v\n", to, opts)
	return nil
}

// encode to Base64 while splitting in multiple rows
func splitBase64(b []byte) []byte {
	out := &bytes.Buffer{}
	enc := base64.NewEncoder(base64.StdEncoding, out)
	for len(b) > 57 {
		enc.Write(b[:57])
		out.Write([]byte{13, 10})
		b = b[57:]
	}
	if len(b) > 0 {
		enc.Write(b)
		enc.Close()
		out.Write([]byte{13, 10})
	}
	return out.Bytes()
}

func (s *session) Data(r io.Reader) error {
	if s.user == "" || s.auth == "" {
		return errors.New("User was not authenticated")
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return errors.New("Error getting DATA content")
	}
	// fmt.Printf("Data %s\n", string(b))

	// see https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0&tabs=http
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/sendMail", s.user)

	body := splitBase64(b)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("Error building POST request for %s", url)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", s.auth)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("Graph API error")
	}

	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return errors.New("Graph API error")
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		fmt.Fprintln(os.Stderr, "Error response from Graph API", string(data))
		return fmt.Errorf("Graph API error status %s", res.Status)
	}

	return nil
}

func (s *session) Reset() {}

func (s *session) Logout() error {
	// fmt.Printf("Logout\n")
	return nil
}

func (s *session) AuthMechanisms() []string {
	return []string{"XOAUTH2"}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	return &auth{s: s}, nil
}

type auth struct {
	s *session
}

func (a *auth) Next(response []byte) (challenge []byte, done bool, err error) {
	// fmt.Printf("Response:\n%s\n", hex.Dump(response))
	if len(response) == 0 {
		return
	}
	valid := true
	if valid && !bytes.HasSuffix(response, []byte{1, 1}) {
		valid = false
	}
	if valid {
		response = response[:len(response)-2]

		for _, field := range bytes.Split(response, []byte{1}) {
			if !valid {
				break
			}
			if bytes.HasPrefix(field, []byte("user=")) {
				email := string(field[5:])
				addr, err := mail.ParseAddress(email)
				if err != nil || addr.Name != "" {
					valid = false
				}
				a.s.user = email
			} else if bytes.HasPrefix(field, []byte("auth=")) {
				val := field[5:]
				if !bytes.HasPrefix(val, []byte("Bearer ")) {
					valid = false
				} else {
					a.s.auth = string(val)
				}
			} else {
				valid = false
			}
		}
	}
	if valid && a.s.user == "" {
		valid = false
	}
	if valid && a.s.auth == "" {
		valid = false
	}
	err = nil
	done = true
	if !valid {
		err = fmt.Errorf("XOAUTH2 string has an invalid format")
	}
	return
}

func main() {
	flag.Parse()

	s := smtp.NewServer(&backend{})

	s.Addr = addr
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	s.Debug = os.Stdout
	s.EnableSMTPUTF8 = true
	s.MaxLineLength = 4096

	log.Println("Starting SMTP server at", addr)
	log.Fatal(s.ListenAndServe())
}
