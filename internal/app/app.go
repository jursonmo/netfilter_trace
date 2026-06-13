package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netfilter_trace/internal/trace"
)

const usage = `nftracepath traces a five-tuple through Linux netfilter.

Usage:
  nftracepath run [flags]

Run flags:
  --proto tcp|udp           L4 protocol
  --src 1.2.3.4             source IPv4
  --sport 12345             optional source port
  --dst 5.6.7.8             destination IPv4
  --dport 80                optional destination port
  --in-iface eth0           optional ingress interface
  --mode listen|active      listen for real traffic or generate local outbound traffic
  --timeout 30s             observation timeout
  --max-events 200          max matching trace/log events before cleanup
  --trace-limit 10/second   kernel TRACE/LOG rate limit
  --trace-limit-burst 20    kernel TRACE/LOG rate limit burst
  --allow-broad-match       allow rules without source and destination ports
  --backend auto|nft|iptables
  --json                    print JSON output
  --target local|ssh
  --ssh-host host           SSH target host
  --ssh-user user           SSH user
  --ssh-port 22             SSH port
  --ssh-key path            SSH private key
  --sudo                    run target commands through sudo -n
`

func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[0] {
	case "run":
		if err := run(args[1:], stdin, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 1
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var (
		proto           string
		src             string
		dst             string
		inIface         string
		mode            string
		backend         string
		target          string
		sshHost         string
		sshUser         string
		sshKey          string
		traceLimit      string
		timeout         time.Duration
		sport           int
		dport           int
		sshPort         int
		maxEvents       int
		limitBurst      int
		jsonOut         bool
		sudo            bool
		allowBroadMatch bool
	)

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&proto, "proto", "", "tcp or udp")
	fs.StringVar(&src, "src", "", "source IPv4")
	fs.IntVar(&sport, "sport", 0, "optional source port")
	fs.StringVar(&dst, "dst", "", "destination IPv4")
	fs.IntVar(&dport, "dport", 0, "optional destination port")
	fs.StringVar(&inIface, "in-iface", "", "optional ingress interface")
	fs.StringVar(&mode, "mode", "", "listen or active")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "observation timeout")
	fs.IntVar(&maxEvents, "max-events", trace.DefaultMaxEvents, "max matching trace/log events before cleanup")
	fs.StringVar(&traceLimit, "trace-limit", trace.DefaultTraceLimit, "kernel TRACE/LOG rate limit")
	fs.IntVar(&limitBurst, "trace-limit-burst", trace.DefaultTraceLimitBurst, "kernel TRACE/LOG rate limit burst")
	fs.BoolVar(&allowBroadMatch, "allow-broad-match", false, "allow rules without source and destination ports")
	fs.StringVar(&backend, "backend", "auto", "auto, nft, or iptables")
	fs.BoolVar(&jsonOut, "json", false, "print JSON")
	fs.StringVar(&target, "target", "", "local or ssh")
	fs.StringVar(&sshHost, "ssh-host", "", "SSH host")
	fs.StringVar(&sshUser, "ssh-user", "", "SSH user")
	fs.IntVar(&sshPort, "ssh-port", 22, "SSH port")
	fs.StringVar(&sshKey, "ssh-key", "", "SSH private key path")
	fs.BoolVar(&sudo, "sudo", false, "run target commands through sudo -n")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reader := bufio.NewReader(stdin)
	promptOptional := !(proto != "" && src != "" && dst != "" && mode != "" && (target != "" || sshHost != ""))
	if err := fillInteractive(reader, stdout, promptOptional, &proto, &src, &sport, &dst, &dport, &inIface, &mode, &target, &sshHost, &sshUser, &sshPort, &sshKey); err != nil {
		return err
	}

	flow, err := trace.NewFlow(proto, src, sport, dst, dport, inIface)
	if err != nil {
		return err
	}
	cfg := trace.RunConfig{
		Flow:            flow,
		Mode:            trace.Mode(mode),
		Backend:         trace.BackendName(backend),
		Timeout:         timeout,
		JSON:            jsonOut,
		MaxEvents:       maxEvents,
		TraceLimit:      traceLimit,
		TraceLimitBurst: limitBurst,
		AllowBroadMatch: allowBroadMatch,
		Target: trace.TargetConfig{
			Kind:    trace.TargetKind(target),
			SSHHost: sshHost,
			SSHUser: sshUser,
			SSHPort: sshPort,
			SSHKey:  sshKey,
			Sudo:    sudo,
		},
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	exec, err := trace.NewExecutor(cfg.Target)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := trace.Run(ctx, exec, cfg)
	if err != nil {
		return err
	}
	if cfg.JSON {
		return trace.WriteJSON(stdout, result)
	}
	return trace.WriteHuman(stdout, result)
}

func fillInteractive(reader *bufio.Reader, out io.Writer, promptOptional bool, proto, src *string, sport *int, dst *string, dport *int, inIface, mode, target, sshHost, sshUser *string, sshPort *int, sshKey *string) error {
	var err error
	if *proto == "" {
		*proto, err = askString(reader, out, "协议 tcp|udp", "tcp")
		if err != nil {
			return err
		}
	}
	if *src == "" {
		*src, err = askString(reader, out, "源 IPv4", "")
		if err != nil {
			return err
		}
	}
	if *sport == 0 && promptOptional {
		*sport, err = askInt(reader, out, "源端口(可空)", 0)
		if err != nil {
			return err
		}
	}
	if *dst == "" {
		*dst, err = askString(reader, out, "目的 IPv4", "")
		if err != nil {
			return err
		}
	}
	if *dport == 0 && promptOptional {
		*dport, err = askInt(reader, out, "目的端口(可空)", 0)
		if err != nil {
			return err
		}
	}
	if *inIface == "" && promptOptional {
		*inIface, err = askString(reader, out, "入网卡(可空)", "")
		if err != nil {
			return err
		}
	}
	if *mode == "" {
		*mode, err = askString(reader, out, "模式 listen|active", "listen")
		if err != nil {
			return err
		}
	}
	if *target == "" {
		if *sshHost != "" {
			*target = string(trace.TargetSSH)
		} else {
			*target, err = askString(reader, out, "目标 local|ssh", "local")
			if err != nil {
				return err
			}
		}
	}
	if trace.TargetKind(*target) == trace.TargetSSH {
		if *sshHost == "" {
			*sshHost, err = askString(reader, out, "SSH host", "")
			if err != nil {
				return err
			}
		}
		if *sshUser == "" && promptOptional {
			*sshUser, err = askString(reader, out, "SSH user(可空)", "")
			if err != nil {
				return err
			}
		}
		if *sshPort == 0 {
			*sshPort, err = askInt(reader, out, "SSH port", 22)
			if err != nil {
				return err
			}
		}
		if *sshKey == "" && promptOptional {
			*sshKey, err = askString(reader, out, "SSH key(可空)", "")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func askString(reader *bufio.Reader, out io.Writer, prompt, def string) (string, error) {
	if def == "" {
		fmt.Fprintf(out, "%s: ", prompt)
	} else {
		fmt.Fprintf(out, "%s [%s]: ", prompt, def)
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		value = def
	}
	return value, nil
}

func askInt(reader *bufio.Reader, out io.Writer, prompt string, def int) (int, error) {
	defText := ""
	if def != 0 {
		defText = strconv.Itoa(def)
	}
	value, err := askString(reader, out, prompt, defText)
	if err != nil {
		return 0, err
	}
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", prompt, err)
	}
	return parsed, nil
}
