package api

import "tlsident/pkg/capture"

type RequestContext struct {
	Connection capture.ConnectionInfo
	TLS        capture.TLSInfo
	HTTP2      capture.HTTP2Info
	Method     string
	Path       string
	Headers    map[string][]string
	Body       []byte
}

type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

type Handler interface {
	Handle(ctx RequestContext) Response
}
