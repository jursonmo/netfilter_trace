package trace

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type Executor interface {
	Shell(ctx context.Context, script string) (string, error)
	Stream(ctx context.Context, script string) (<-chan string, <-chan error, error)
	Target() TargetConfig
}

type LocalExecutor struct {
	target TargetConfig
}

type SSHExecutor struct {
	target TargetConfig
}

func NewExecutor(target TargetConfig) (Executor, error) {
	if target.Kind == "" {
		target.Kind = TargetLocal
	}
	if target.Kind == TargetLocal {
		return LocalExecutor{target: target}, nil
	}
	if target.Kind == TargetSSH {
		if target.SSHHost == "" {
			return nil, errors.New("ssh target requires host")
		}
		if target.SSHPort == 0 {
			target.SSHPort = 22
		}
		return SSHExecutor{target: target}, nil
	}
	return nil, fmt.Errorf("unsupported target %q", target.Kind)
}

func (e LocalExecutor) Target() TargetConfig {
	return e.target
}

func (e LocalExecutor) Shell(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func (e LocalExecutor) Stream(ctx context.Context, script string) (<-chan string, <-chan error, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	return startStream(cmd)
}

func (e SSHExecutor) Target() TargetConfig {
	return e.target
}

func (e SSHExecutor) Shell(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh", e.args(script)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func (e SSHExecutor) Stream(ctx context.Context, script string) (<-chan string, <-chan error, error) {
	cmd := exec.CommandContext(ctx, "ssh", e.args(script)...)
	return startStream(cmd)
}

func (e SSHExecutor) args(script string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-p", strconv.Itoa(e.target.SSHPort),
	}
	if e.target.SSHKey != "" {
		args = append(args, "-i", e.target.SSHKey)
	}
	dest := e.target.SSHHost
	if e.target.SSHUser != "" {
		dest = e.target.SSHUser + "@" + dest
	}
	args = append(args, dest, "sh", "-c", shellQuote(script))
	return args
}

func startStream(cmd *exec.Cmd) (<-chan string, <-chan error, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	lines := make(chan string, 128)
	errs := make(chan error, 3)
	var wg sync.WaitGroup
	scan := func(r io.Reader) {
		defer wg.Done()
		s := bufio.NewScanner(r)
		buf := make([]byte, 0, 64*1024)
		s.Buffer(buf, 1024*1024)
		for s.Scan() {
			lines <- s.Text()
		}
		if err := s.Err(); err != nil {
			errs <- err
		}
	}
	wg.Add(2)
	go scan(stdout)
	go scan(stderr)
	go func() {
		wg.Wait()
		close(lines)
		if err := cmd.Wait(); err != nil {
			errs <- err
		}
		close(errs)
	}()
	return lines, errs, nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '=' || r == '+' || r == ',' || r == '%' || r == '@' || r == '[' || r == ']' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func shellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func privileged(script string, sudo bool) string {
	if !sudo {
		return script
	}
	return "sudo -n sh -c " + shellQuote(script)
}
