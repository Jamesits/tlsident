package api

import (
	"log/slog"

	"tlsident/pkg/api/anthropic"
	"tlsident/pkg/api/common"
	"tlsident/pkg/api/peetws"
	"tlsident/pkg/capture"
)

type Router struct {
	anthropic common.Handler
	peetws    common.Handler
}

func New(store *capture.Store, logger *slog.Logger) *Router {
	return &Router{
		anthropic: anthropic.NewService(store, logger),
		peetws:    peetws.NewService(),
	}
}

func (r *Router) Handle(ctx common.RequestContext) common.Response {
	switch ctx.Path {
	case "/api/all", "/api/clean", "/api/tls":
		return r.peetws.Handle(ctx)
	default:
		return r.anthropic.Handle(ctx)
	}
}
