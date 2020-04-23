package prober

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"time"

	"mellium.im/sasl"
	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"
)

type StreamInfo struct {
	Negotiated      bool
	SASLOffered     bool
	SASLMechanisms  []string
	DialbackOffered bool
}

type StartTLSCapture struct {
	cfg            *tls.Config
	CapturedWriter io.ReadWriter
}

func NewCapturingStartTLS(cfg *tls.Config) *StartTLSCapture {
	return &StartTLSCapture{
		cfg:            cfg,
		CapturedWriter: nil,
	}
}

func (c *StartTLSCapture) ToStreamFeature() xmpp.StreamFeature {
	orig_stream_feature := xmpp.StartTLS(true, c.cfg)
	return xmpp.StreamFeature{
		Name:       orig_stream_feature.Name,
		Prohibited: orig_stream_feature.Prohibited,
		List:       orig_stream_feature.List,
		Parse:      orig_stream_feature.Parse,
		Negotiate: func(ctx context.Context, session *xmpp.Session, data interface{}) (mask xmpp.SessionState, rw io.ReadWriter, err error) {
			mask, rw, err = orig_stream_feature.Negotiate(ctx, session, data)
			c.CapturedWriter = rw
			return
		},
	}
}

func noSendingFeatures(ctx context.Context, e xmlstream.TokenWriter, start xml.StartElement) (req bool, err error) {
	return false, errors.New("sending features not supported")
}

func CheckSASLOffered(offered *bool, mechanisms *[]string) xmpp.StreamFeature {
	orig_stream_feature := xmpp.SASL("", "", sasl.Plain)
	return xmpp.StreamFeature{
		Name:       orig_stream_feature.Name,
		Prohibited: xmpp.Authn,
		List:       noSendingFeatures,
		Parse: func(ctx context.Context, r xml.TokenReader, start *xml.StartElement) (req bool, data interface{}, err error) {
			req, data, err = orig_stream_feature.Parse(ctx, r, start)
			*offered = true
			*mechanisms = data.([]string)
			return req, data, err
		},
		Negotiate: func(ctx context.Context, session *xmpp.Session, data interface{}) (mask xmpp.SessionState, rw io.ReadWriter, err error) {
			return xmpp.Ready, nil, nil
		},
	}
}

func CheckDialbackOffered(offered *bool) xmpp.StreamFeature {
	return xmpp.StreamFeature{
		Name: xml.Name{
			Space: "urn:xmpp:features:dialback",
			Local: "dialback",
		},
		Prohibited: xmpp.Authn,
		List:       noSendingFeatures,
		Parse: func(ctx context.Context, r xml.TokenReader, start *xml.StartElement) (req bool, data interface{}, err error) {
			*offered = true
			parsed := struct {
				XMLName xml.Name `xml:"urn:xmpp:features:dialback dialback"`
			}{}
			err = xml.NewTokenDecoder(r).DecodeElement(&parsed, start)
			return false, nil, err
		},
		Negotiate: func(ctx context.Context, session *xmpp.Session, data interface{}) (mask xmpp.SessionState, rw io.ReadWriter, err error) {
			return xmpp.Ready, nil, nil
		},
	}
}

type RegisterQuery struct {
	XMLName      xml.Name `xml:"jabber:iq:register query"`
	Instructions string   `xml:"jabber:iq:register instructions"`
	Username     string   `xml:"jabber:iq:register username"`
	Password     string   `xml:"jabber:iq:register password"`
	Email        string   `xml:"jabber:iq:register email"`
}

func (r *RegisterQuery) TokenReader() xml.TokenReader {
	return xmlstream.Wrap(
		xmlstream.MultiReader(
			xmlstream.Wrap(
				xmlstream.Token(xml.CharData(r.Username)),
				xml.StartElement{Name: xml.Name{
					Local: "username",
				}},
			),
			xmlstream.Wrap(
				xmlstream.Token(xml.CharData(r.Password)),
				xml.StartElement{Name: xml.Name{
					Local: "password",
				}},
			),
			xmlstream.Wrap(
				xmlstream.Token(xml.CharData(r.Email)),
				xml.StartElement{Name: xml.Name{
					Local: "email",
				}},
			),
		),
		xml.StartElement{Name: xml.Name{
			Space: "jabber:iq:register",
			Local: "query",
		}},
	)
}

func randomAccountName(prefix string) (string, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to generate random name: %s", err.Error())
	}
	return fmt.Sprintf(
		"%s%s",
		prefix,
		hex.EncodeToString(buf),
	), nil
}

func randomPassword() (string, error) {
	buf := make([]byte, 12)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %s", err.Error())
	}
	return hex.EncodeToString(buf), nil
}

func Register(prefix string, server string, account *jid.JID, password *string) xmpp.StreamFeature {
	return xmpp.StreamFeature{
		Name: xml.Name{
			Space: "http://jabber.org/features/iq-register",
			Local: "register",
		},
		Prohibited: xmpp.Authn,
		Necessary:  xmpp.Secure,
		List:       noSendingFeatures,
		Parse: func(ctx context.Context, r xml.TokenReader, start *xml.StartElement) (req bool, data interface{}, err error) {
			parsed := struct {
				XMLName xml.Name `xml:"http://jabber.org/features/iq-register register"`
			}{}
			err = xml.NewTokenDecoder(r).DecodeElement(&parsed, start)
			return true, nil, err
		},
		Negotiate: func(ctx context.Context, session *xmpp.Session, data interface{}) (mask xmpp.SessionState, rw io.ReadWriter, err error) {
			username, err := randomAccountName(prefix)
			if err != nil {
				return xmpp.SessionState(0), nil, err
			}
			*password, err = randomPassword()
			if err != nil {
				return xmpp.SessionState(0), nil, err
			}
			*account, err = jid.New(username, server, "")
			if err != nil {
				return xmpp.SessionState(0), nil, err
			}

			err = session.Send(
				ctx,
				stanza.IQ{
					Type: stanza.SetIQ,
				}.Wrap((&RegisterQuery{
					Username: username,
					Password: *password,
				}).TokenReader()),
			)

			if err != nil {
				return xmpp.SessionState(0), nil, fmt.Errorf("registration failed: %s", err.Error())
			}

			response := struct {
				stanza.IQ
				Error stanza.Error  `xml:"jabber:client error"`
				Reply RegisterQuery `xml:"jabber:iq:register query"`
			}{}
			d := xml.NewTokenDecoder(session.TokenReader())
			start_token, err := d.Token()
			if err != nil {
				return xmpp.SessionState(0), nil, fmt.Errorf("failed to obtain response token: %s", err.Error())
			}
			start := start_token.(xml.StartElement)
			err = d.DecodeElement(&response, &start)
			if err != nil {
				return xmpp.SessionState(0), nil, fmt.Errorf("failed to parse response: %s", err.Error())
			}

			if response.Type == stanza.ErrorIQ {
				tmp := &stanza.Error{}
				*tmp = response.Error
				return xmpp.SessionState(0), nil, tmp
			}

			return xmpp.Ready, nil, nil
		},
	}
}

func traceStreamFeature(f xmpp.StreamFeature, t *time.Time) (result xmpp.StreamFeature) {
	result = f
	result.Negotiate = func(ctx context.Context, session *xmpp.Session, data interface{}) (mask xmpp.SessionState, rw io.ReadWriter, err error) {
		mask, rw, err = f.Negotiate(ctx, session, data)
		*t = time.Now()
		return
	}
	return
}

func isAnyContainedIn(needles []string, haystack []string) bool {
	for _, needle := range needles {
		for _, hay := range haystack {
			if needle == hay {
				return true
			}
		}
	}
	return false
}

func isAllContainedIn(needles []string, haystack []string) bool {
	for _, needle := range needles {
		found := false
		for _, hay := range haystack {
			if needle == hay {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ValidateSASLMechanisms(mechanisms []string, forbidden []string, required []string) bool {
	if forbidden != nil && isAnyContainedIn(forbidden, mechanisms) {
		return false
	}
	if required != nil && !isAllContainedIn(required, mechanisms) {
		return false
	}
	return true
}
