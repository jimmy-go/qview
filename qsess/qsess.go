// Package qsess contains QRA integration with gorilla sessions cookie store.
//
// MIT License
//
// Copyright (c) 2017 Angel Del Castillo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package qsess

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/jimmy-go/qra"
)

var (
	cstore *sessions.CookieStore

	// sessName custom session name
	sessName = DefaultSessionName

	loginURL = "/login"

	// ErrInvalidSessionName error.
	ErrInvalidSessionName = errors.New("session name must be greater than 10 characters")
	// ErrKeys error.
	ErrKeys = errors.New("keys not set")
)

const (
	// DefaultSessionName name.
	DefaultSessionName = "rSZ6m9PTHUAK0njapwumqaJIgi5zt7"
)

// Options struct.
type Options struct {
	Keys        string
	Separator   string
	SessionName string
	LoginURL    string
}

// Configure inits the cookie store.
func Configure(o *Options) error {
	// log.Printf("Configure : o [%#v]", o)
	if o == nil {
		return errors.New("options not set")
	}
	sep := " "
	if len(o.Separator) > 0 {
		sep = o.Separator
	}

	ks := strings.Split(o.Keys, sep)
	if len(ks) < 1 {
		return ErrKeys
	}
	if len(o.SessionName) > 1 {
		sessName = o.SessionName
	}
	if len(sessName) < 1 {
		return ErrInvalidSessionName
	}
	if len(o.LoginURL) > 1 {
		loginURL = o.LoginURL
	}

	var ksb []byte
	for i := range ks {
		ksb = append(ksb, []byte(ks[i])...)
	}
	cstore = sessions.NewCookieStore(ksb)
	return nil
}

// Handler middleware.
func Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handler : uri [%s]", r.RequestURI)
		// handler must apply to all uri except for /login.
		if r.RequestURI == loginURL {
			h.ServeHTTP(w, r)
			return
		}

		token, err := cookToken(r, w)
		if err != nil {
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}

		ctx := Context{
			Token: token,
		}

		// validate user has permission to view this URL (view)
		// FIXME; proposed approach is allow specific urls.

		err = qra.Search(ctx, nil, "read:webadmin")
		if err != nil {
			log.Printf("Handler : err [%s]", err)
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Login endpoint.
func Login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Printf("Login : parse form [%s]", err)
			return
		}

		username := r.Form.Get("username")
		p := r.Form.Get("password")

		ctx := Context{
			Username: username,
		}
		var token string
		err := qra.Authenticate(ctx, p, &token)
		if err != nil {
			log.Printf("Handler : err [%s]", err)
			w.WriteHeader(http.StatusUnauthorized)
			if _, err := fmt.Fprint(w, "unauthorized access"); err != nil {
				log.Printf("Login : write unauthorized response : err [%s]", err)
			}
			return
		}

		err = cookSet(r, w, token)
		if err != nil {
			log.Printf("Login : cookie store token : err [%s]", err)
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

// Logout endpoint.
func Logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Printf("Logout : parse form [%s]", err)
			return
		}

		token, err := cookToken(r, w)
		if err != nil {
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}

		ctx := Context{
			Token: token,
		}

		err = qra.Close(ctx)
		if err != nil {
			log.Printf("Session Handler : err [%s]", err)
			w.WriteHeader(http.StatusUnauthorized)
			if _, err := fmt.Fprint(w, "unauthorized access"); err != nil {
				log.Printf("Logout : write unauthorized response : err [%s]", err)
			}
			return
		}

		err = cookDestroy(r, w)
		if err != nil {
			log.Printf("Logout : delete cookie : err [%s]", err)
		}

		http.Redirect(w, r, loginURL, http.StatusSeeOther)
	})
}

func cookSet(r *http.Request, w http.ResponseWriter, token string) error {
	sess, err := cstore.Get(r, sessName)
	if err != nil {
		return err
	}
	sess.Values["token"] = token
	// TODO; add expiration date.
	err = sess.Save(r, w)
	if err != nil {
		return err
	}
	return nil
}

func cookToken(r *http.Request, w http.ResponseWriter) (string, error) {
	sess, err := cstore.Get(r, sessName)
	if err != nil {
		return "", err
	}
	token, ok := sess.Values["token"].(string)
	if !ok {
		return "", errors.New("token session not set")
	}
	return token, nil
}

func cookDestroy(r *http.Request, w http.ResponseWriter) error {
	sess, err := cstore.Get(r, sessName)
	if err != nil {
		return err
	}
	sess.Options.MaxAge = -1
	err = sess.Save(r, w)
	if err != nil {
		return err
	}
	return nil
}

// Context satisfies qra.Identity interface.
type Context struct {
	Username string
	Token    string
}

// Me method satisfies qra.Identity.
func (c Context) Me() string {
	return c.Username
}

// Session method satisfies qra.Identity.
func (c Context) Session(dst interface{}) error {
	p := reflect.ValueOf(dst)
	v := p.Elem()
	v.SetString(c.Token)
	return nil
}
