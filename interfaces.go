package dnsproxy

import (
	"context"
	dm "golang.org/x/net/dns/dnsmessage"
)

type Resolver interface {
	Resolve(ctx context.Context, req *dm.Message) (*dm.Message, error)
	GetName() string
}
