package prober

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"io"
	"time"

	"mellium.im/sasl"
	"mellium.im/xmlstream"
	"mellium.im/xmpp"
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

func CheckSASLOffered(offered *bool, mechanisms *[]string) xmpp.StreamFeature {
	orig_stream_feature := xmpp.SASL("", "", sasl.Plain)
	return xmpp.StreamFeature{
		Name:       orig_stream_feature.Name,
		Prohibited: xmpp.Authn,
		List: func(ctx context.Context, e xmlstream.TokenWriter, start xml.StartElement) (req bool, err error) {
			return false, errors.New("sending features not supported")
		},
		Parse: orig_stream_feature.Parse,
		Negotiate: func(ctx context.Context, session *xmpp.Session, data interface{}) (mask xmpp.SessionState, rw io.ReadWriter, err error) {
			*offered = true
			*mechanisms = data.([]string)
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
	for _, needle := range(needles) {
		for _, hay := range(haystack) {
			if needle == hay {
				return true
			}
		}
	}
	return false
}

func isAllContainedIn(needles []string, haystack []string) bool {
	for _, needle := range(needles) {
		found := false
		for _, hay := range(haystack) {
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
