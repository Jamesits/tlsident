package api

import (
	"tlsident/pkg/capture"
	"tlsident/pkg/tlsfp"
)

type RequestContext struct {
	Connection  capture.ConnectionInfo
	ClientHello *tlsfp.ClientHello
	TLS         capture.TLSInfo
	HTTP2       capture.HTTP2Info
	Protocol    string
	Host        string
	ClientPort  int
	HTTP1       HTTP1RequestInfo
	HTTP2Req    HTTP2RequestInfo
	Method      string
	Path        string
	Headers     map[string][]string
	Body        []byte
}

type HeaderField struct {
	Name  string
	Value string
}

type HTTP1RequestInfo struct {
	HeaderLines []string
}

type HTTP2RequestInfo struct {
	StreamID          uint32
	HeaderBlockLength int
	HeaderFields      []HeaderField
	EndStream         bool
}

type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

type Handler interface {
	Handle(ctx RequestContext) Response
}
