package webui

import (
	"net/http"

	"github.com/kvmukilan/livewire/internal/engine"
)

type flowInfo struct {
	Index     int    `json:"index"`
	Client    string `json:"client"`
	Server    string `json:"server"`
	ServerIP  string `json:"serverIP"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Packets   int    `json:"packets"`
	Handshake bool   `json:"handshake"`
}

// handleFlows loads a pcap and lists its TCP flows for the flow picker.
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pcap string `json:"pcap"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	path, err := s.pcapPath(req.Pcap)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	recs, _, err := loadPcap(path)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	flows := engine.ExtractFlows(recs)
	out := make([]flowInfo, 0, len(flows))
	for i, f := range flows {
		out = append(out, flowInfo{
			Index:     i,
			Client:    f.Client.String(),
			Server:    f.Server.String(),
			ServerIP:  f.Server.Addr.String(),
			Port:      int(f.Server.Port),
			Proto:     engine.ProtocolGuess(f.Server.Port, f.Client.Port),
			Packets:   len(f.Packets),
			Handshake: f.HasSyn && f.HasSynAck,
		})
	}
	writeJSON(w, out)
}
