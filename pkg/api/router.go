package api

type Router struct {
	anthropic Handler
	peetws    Handler
}

func NewRouter(anthropic, peetws Handler) *Router {
	return &Router{
		anthropic: anthropic,
		peetws:    peetws,
	}
}

func (r *Router) Handle(ctx RequestContext) Response {
	switch ctx.Path {
	case "/api/all", "/api/clean", "/api/tls":
		return r.peetws.Handle(ctx)
	default:
		return r.anthropic.Handle(ctx)
	}
}
