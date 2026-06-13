package trace

import (
	"context"
	"fmt"
	"net"
	"time"
)

func maybeTriggerActive(ctx context.Context, exec Executor, cfg RunConfig) string {
	if cfg.Flow.InIface != "" {
		return "active mode cannot synthesize traffic arriving on a specific ingress interface; listening for real traffic instead"
	}
	if exec.Target().Kind != TargetLocal {
		return "active mode is only implemented for local targets in v1; listening for real traffic instead"
	}
	errCh := make(chan error, 1)
	go func() {
		shortSleep(ctx)
		errCh <- triggerLocalActive(ctx, cfg.Flow)
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return "active probe failed; continuing to listen: " + err.Error()
		}
		return ""
	case <-ctx.Done():
		return ""
	}
}

func triggerLocalActive(ctx context.Context, f Flow) error {
	if f.DstPort == 0 {
		return fmt.Errorf("active mode requires destination port; omit --mode active or provide --dport")
	}
	switch f.Proto {
	case ProtoTCP:
		local := &net.TCPAddr{IP: f.SrcIP.To4(), Port: f.SrcPort}
		remote := &net.TCPAddr{IP: f.DstIP.To4(), Port: f.DstPort}
		d := net.Dialer{
			LocalAddr: local,
			Timeout:   3 * time.Second,
		}
		conn, err := d.DialContext(ctx, "tcp4", remote.String())
		if err != nil {
			return err
		}
		return conn.Close()
	case ProtoUDP:
		local := &net.UDPAddr{IP: f.SrcIP.To4(), Port: f.SrcPort}
		remote := &net.UDPAddr{IP: f.DstIP.To4(), Port: f.DstPort}
		d := net.Dialer{
			LocalAddr: local,
			Timeout:   3 * time.Second,
		}
		conn, err := d.DialContext(ctx, "udp4", remote.String())
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write([]byte("nftracepath\n"))
		return err
	default:
		return fmt.Errorf("unsupported proto %s", f.Proto)
	}
}
