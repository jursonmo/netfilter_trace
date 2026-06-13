package trace

import (
	"fmt"
	"strconv"
	"strings"
)

func nftMatch(f Flow, includeInIface bool) string {
	parts := []string{}
	if includeInIface && f.InIface != "" {
		parts = append(parts, "iifname", strconv.Quote(f.InIface))
	}
	parts = append(parts,
		"ip", "saddr", f.Src4(),
		"ip", "daddr", f.Dst4(),
		"meta", "l4proto", string(f.Proto),
	)
	if f.SrcPort > 0 {
		parts = append(parts, string(f.Proto), "sport", strconv.Itoa(f.SrcPort))
	}
	if f.DstPort > 0 {
		parts = append(parts, string(f.Proto), "dport", strconv.Itoa(f.DstPort))
	}
	return strings.Join(parts, " ")
}

func iptablesMatchArgs(f Flow, includeInIface bool) []string {
	args := []string{
		"-p", string(f.Proto),
		"-s", f.Src4(),
		"-d", f.Dst4(),
	}
	if f.SrcPort > 0 {
		args = append(args, "--sport", strconv.Itoa(f.SrcPort))
	}
	if f.DstPort > 0 {
		args = append(args, "--dport", strconv.Itoa(f.DstPort))
	}
	if includeInIface && f.InIface != "" {
		args = append(args, "-i", f.InIface)
	}
	return args
}

func comment(runID, suffix string) string {
	return fmt.Sprintf("nftracepath:%s:%s", runID, suffix)
}

func logPrefix(runID, suffix string) string {
	return fmt.Sprintf("NFTP:%s:%s ", runID, suffix)
}
