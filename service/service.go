package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"gopkg.in/yaml.v2"
)

const (
	dnsRuleDisplayName = "OpenFortiVPN WSL Proxy"
	wslStartupGrace    = 5 * time.Second
)

// ANSI escape sequence matcher (CSI and other common forms)
var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

type Config struct {
	Server      string   `yaml:"server"`
	Domains     []string `yaml:"domains"`
	Nameservers []string `yaml:"nameservers"`
}

type myService struct {
	yamlPath  string
	config    Config
	wslCmd    *exec.Cmd
	wslExitCh chan struct{}
}

func (m *myService) loadConfig() error {
	data, err := os.ReadFile(m.yamlPath)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &m.config)
}

func (m *myService) validateConfig() error {
	if m.config.Server == "" {
		return fmt.Errorf("config validation failed: server is empty")
	}
	if len(m.config.Domains) == 0 {
		return fmt.Errorf("config validation failed: domains list is empty")
	}
	if len(m.config.Nameservers) == 0 {
		return fmt.Errorf("config validation failed: nameservers list is empty")
	}
	return nil
}

func (m *myService) addDNSRule() error {
	if len(m.config.Domains) == 0 || len(m.config.Nameservers) == 0 {
		return fmt.Errorf("domains or nameservers list is empty")
	}

	m.removeDNSRule()

	domains := strings.Join(m.config.Domains, `","`)
	nameservers := strings.Join(m.config.Nameservers, `","`)

	psCmd := fmt.Sprintf(`Add-DnsClientNrptRule -DisplayName '%s' -Namespace @("%s") -NameServers @("%s")`, dnsRuleDisplayName, domains, nameservers)
	cmd := exec.Command("powershell", "-Command", psCmd)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("PowerShell error: %s", string(output))
		return fmt.Errorf("failed to add DNS rule: %w", err)
	}
	return nil
}

func (m *myService) removeDNSRule() {
	psCmd := fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq '%s' } | Remove-DnsClientNrptRule -Force`, dnsRuleDisplayName)
	cmd := exec.Command("powershell", "-Command", psCmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Failed to remove DNS rule '%s': %v (output: %s)", dnsRuleDisplayName, err, string(output))
	}
}

// sanitizeWSL keeps printable runes, strips ANSI (already removed earlier),
// drops control characters and leading spaces that come from CR overwrites.
func sanitizeWSL(s string) string {
	if s == "" {
		return s
	}
	// Strip ANSI escape sequences first.
	s = ansiSeq.ReplaceAllString(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// Skip control chars, tabs (avoid indentation drift), and non-printables.
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 32 || (r >= 0x7f && r <= 0x9f) {
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimLeft(b.String(), " \u00A0")
	return out
}

// streamAndLog processes a reader byte-by-byte, honoring carriage returns as
// line resets (progress rewrite style). Newlines flush the current buffer.
func streamAndLog(r io.Reader, prefix string, logLine func(string, string)) {
	buf := make([]byte, 4096)
	var line bytes.Buffer
	atLineStart := true // track logical start after CR so we can drop clearing spaces
	flush := func() {
		if line.Len() == 0 {
			return
		}
		raw := line.String()
		line.Reset()
		atLineStart = true
		clean := sanitizeWSL(raw)
		if clean == "" {
			return
		}
		logLine(prefix, clean)
	}
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := buf[:n]
			for len(data) > 0 {
				b := data[0]
				data = data[1:]
				switch b {
				case '\r':
					// Carriage return: reset current logical line; following spaces are clearing padding.
					line.Reset()
					atLineStart = true
				case '\n':
					flush()
				default:
					if atLineStart {
						// Drop leading spaces/tabs inserted to erase previous longer content.
						if b == ' ' || b == '\t' {
							continue
						}
						atLineStart = false
					}
					line.WriteByte(b)
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("WSL[%s] stream error: %v", prefix, err)
			}
			break
		}
	}
	flush()
}

func (m *myService) startWSLProcess() error {
	cmd := exec.Command("wsl", "-d", "OpenFortiVPN", "--", "/usr/local/bin/run-vpn", m.config.Server)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.removeDNSRule()
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		m.removeDNSRule()
		return fmt.Errorf("stderr pipe: %w", err)
	}

	var earlyBuf bytes.Buffer
	var authOnce sync.Once
	authRe := regexp.MustCompile(`Authenticate at '([^']+)'`)

	openAuthURL := func(u string) {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
		log.Printf("Opened authentication URL: %s", u)
	}

	logLine := func(prefix, line string) {
		log.Printf("WSL[%s] %s", prefix, line)
		if earlyBuf.Len() < 4096 {
			earlyBuf.WriteString(prefix + ": " + line + "\n")
		}
		if m := authRe.FindStringSubmatch(line); len(m) == 2 {
			url := m[1]
			authOnce.Do(func() { openAuthURL(url) })
		}
	}

	if err := cmd.Start(); err != nil {
		m.removeDNSRule()
		return err
	}
	m.wslCmd = cmd
	m.wslExitCh = make(chan struct{})

	go streamAndLog(stdout, "out", logLine)
	go streamAndLog(stderr, "err", logLine)

	go func() { _ = cmd.Wait(); close(m.wslExitCh) }()

	select {
	case <-m.wslExitCh:
		state := "unknown"
		if cmd.ProcessState != nil {
			state = cmd.ProcessState.String()
		}
		m.removeDNSRule()
		return fmt.Errorf("WSL process exited prematurely (%s). Initial output:\r\n%s", state, earlyBuf.String())
	case <-time.After(wslStartupGrace):
	}
	return nil
}

func (m *myService) stopWSLProcess() {
	_ = exec.Command("wsl", "--terminate", "OpenFortiVPN").Run()
}

func (m *myService) waitWSLExit(timeout time.Duration) {
	if m.wslExitCh == nil {
		return
	}
	select {
	case <-m.wslExitCh:
	case <-time.After(timeout):
		log.Printf("WSL process did not exit within %s", timeout)
	}
}

func run(yamlPath string) error {
	svc := &myService{yamlPath: yamlPath}

	if err := svc.loadConfig(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := svc.validateConfig(); err != nil {
		return err
	}
	if err := svc.addDNSRule(); err != nil {
		return fmt.Errorf("add DNS rule: %w", err)
	}
	if err := svc.startWSLProcess(); err != nil {
		return fmt.Errorf("start WSL process: %w", err)
	}

	log.Println("Running. Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	log.Println("Stopping...")
	signal.Stop(sigChan)

	svc.stopWSLProcess()
	svc.removeDNSRule()
	svc.waitWSLExit(5 * time.Second)

	log.Println("Stopped.")
	return nil
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <config.yaml>", os.Args[0])
	}
	yamlPath := os.Args[1]
	if err := run(yamlPath); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}
