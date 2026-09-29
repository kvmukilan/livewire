package hoststack

func reconcileOwned(r Rule) error {
	s := &iptablesSuppressor{rule: r, bin: iptablesBin(r), run: execRunner, armed: true}
	return s.Disarm()
}
