package dnsproxy

import (
	"fmt"
	dm "golang.org/x/net/dns/dnsmessage"
	"net"
)

func ReprQuestionShort(q *dm.Question) string {
	return fmt.Sprintf("[%v:%v]", q.Type, q.Name)
}

func reprResouceShort(r *dm.Resource) (repr string) {
	repr += fmt.Sprintf("[%v:%v][ttl:%v]", r.Header.Type, r.Header.Name, r.Header.TTL)
	switch cr := r.Body.(type) {
	case *dm.AResource:
		repr += fmt.Sprintf("[ip:%v]", net.IP(cr.A[:]))
	case *dm.AAAAResource:
		repr += fmt.Sprintf("[ip:%v]", net.IP(cr.AAAA[:]))
	}
	return
}

func b2i(b bool) int {
	if b {
		return 1
	} else {
		return 0
	}
}

func ReprMessageShort(m *dm.Message) (repr string) {
	if m == nil {
		return "(nil)"
	}

	repr += fmt.Sprintf("[ID:%v][OP:%v][RCode:%d]", m.ID, m.OpCode, m.RCode)
	repr += "[flags:"
	if m.Response {
		repr += "+R"
	}
	if m.Authoritative {
		repr += "+A"
	}
	if m.Truncated {
		repr += "+T"
	}
	if m.RecursionDesired {
		repr += "+RD"
	}
	if m.RecursionAvailable {
		repr += "+RA"
	}
	repr += "]"

	repr += " [Questions]"
	for i := range m.Questions {
		repr += ReprQuestionShort(&m.Questions[i])
	}

	if len(m.Answers) > 0 {
		repr += " [Answers]"
	}
	for i := range m.Answers {
		repr += reprResouceShort(&m.Answers[i])
	}

	if len(m.Authorities) > 0 {
		repr += " [Authorities]"
	}
	for i := range m.Authorities {
		repr += reprResouceShort(&m.Authorities[i])
	}

	if len(m.Additionals) > 0 {
		repr += " [Additionals]"
	}
	for i := range m.Additionals {
		repr += reprResouceShort(&m.Additionals[i])
	}

	return
}
