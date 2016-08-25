package main

import (
	"net"

	"github.com/miekg/dns"
)

func hashQuestion(q *dns.Question) [32]byte {
	inp := append([]byte{q.Qtype, q.Qclass}, []byte(q.Name)...)
	return sha256.Sum256(inp)
}

type response struct {
	// probably going to want something more complex later like func execution...?
	msg *dns.Msg
	raw []byte
}

type interceptor struct {
	l net.Listener
	// map of network + IPs -> map of question hashes -> answer
	rules map[string]map[[32]byte]*response
}

func (i *interceptor) lookupRule(addr string, q *dns.Question) (*response, error) {
	qm, present := i.rules[addr]
	if !present {
		return nil, fmt.Errorf("No rules for address %s", addr)
	}
	r, present := qm[hashQuestion(q)]
	if !present {
		return nil, fmt.Errorf("No answers for %s question %s", addr, q.String())
	}
	return r, nil
}

func (i *interceptor) sendResponse(conn *dns.Conn, r *response) err {
	if r.raw != nil {
		_, err := conn.Write(r.raw)
		return err
	}
	if r.msg != nil {
		return conn.WriteMsg(r.msg)
	}
	return nil // bad :/
}

func (i *interceptor) process(conn *dns.Conn) {
	defer conn.Close()

	ra := conn.RemoteAddr()
	a, _ := net.SplitHostPort(ra.String())
	a = ra.Network() + a

	msg, err := conn.ReadMsg()
	if err != nil {
		// log
		return
	}
	if len(msg.Question) == 0 {
		// log
		return
	}

	r, err := i.lookupRule(a, msg.Question[0])
	if err != nil {
		// log
		return
	}

	err = i.sendResponse(conn, r)
	if err != nil {
		// log
		return
	}
}

func (i *interceptor) run(l *net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			// log
			continue
		}
		go i.process(&dns.Conn{Conn: conn})
	}
}

func (i *interceptor) listen(udpListener, tcpListener *net.Listener) {
	if udpListener != nil {
		go i.run(udpListener)
	}
	if tcpListener != nil {
		go i.run(tcpListener)
	}
}
