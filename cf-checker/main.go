package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/miekg/dns"
)

// ── Builtin Domains (judge.sh style) ─────────────────────────

var builtinDomains = []string{
	"cdnjs.com",
	"cdt.org",
	"cloudeereviews.com",
	"cloudflare-test.judge.sh",
	"cloudflare-test-target.judge.sh",
	"corporateclash.net",
	"d3js.org",
	"domjh.com",
	"domjh.net",
	"firing.it",
	"getbootstrap.com",
	"git-scm.com",
	"html5boilerplate.com",
	"i.gyazo.com",
	"js.org",
	"judge2020.com",
	"judge2020.me",
	"manfredi.io",
	"medium.com",
	"nodejs.org",
	"quizlet.com",
	"sontusdatos.org",
	"unpkg.com",
	"www.amnestyusa.org",
	"www.artstation.com",
	"www.codeguard.com",
	"www.counterextremism.com",
	"www.digitalocean.com",
	"www.findlaw.com",
	"www.loc.gov",
	"www.ndi.org",
	"www.opentech.fund",
	"www.shoutmeloud.com",
	"www.techagainstterrorism.org",
	"www.thetrevorproject.org",
	"www.zendesk.com",
}

// ── Result struct ────────────────────────────────────────────

type result struct {
	Domain string
	IP     string
	IsIPv6 bool
	Ping1  string
	Ping2  string
	Node   string
	Status string // "waiting", "testing", "done", "error"
}

// ── Messages ─────────────────────────────────────────────────

type resultMsg struct {
	Index  int
	Result result
}

type tickMsg time.Time
type doneMsg struct{}

// ── Styles ───────────────────────────────────────────────────

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FFFF")).
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#00FFFF")).
			Padding(0, 2).
			Align(lipgloss.Center)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	greenStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF88"))

	yellowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFD700"))

	redStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4444"))

	cyanStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00DDFF"))

	magentaStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF77FF"))

	spinChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
)

// ── DNS Resolution ───────────────────────────────────────────

func dnsResolve(domain, server string, qtype uint16) string {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil || r == nil {
		return ""
	}

	for _, ans := range r.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				return rr.A.String()
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				return rr.AAAA.String()
			}
		case *dns.CNAME:
			// Follow CNAME: resolve the target
			if qtype == dns.TypeA {
				result := dnsResolve(rr.Target, server, qtype)
				if result != "" {
					return result
				}
			}
		}
	}
	return ""
}

// ── Ping ─────────────────────────────────────────────────────

var pingRegex = regexp.MustCompile(`time[=<](\d+\.?\d*)\s*ms`)

func doPing(ip string) string {
	var cmd *exec.Cmd
	if strings.Contains(ip, ":") {
		cmd = exec.Command("ping", "-6", "-c", "1", "-W", "2", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", ip)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "-"
	}

	match := pingRegex.FindSubmatch(out)
	if match != nil {
		return string(match[1])
	}
	return "-"
}

// ── CF-Ray Header ────────────────────────────────────────────

var cfRayRegex = regexp.MustCompile(`-([A-Z]{3,4})$`)

func getCFNode(domain, ip string, isIPv6 bool) string {
	dialer := &net.Dialer{Timeout: 4 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			port := "443"
			if isIPv6 {
				return dialer.DialContext(ctx, "tcp6", "["+ip+"]:"+port)
			}
			return dialer.DialContext(ctx, "tcp4", ip+":"+port)
		},
		TLSClientConfig: &tls.Config{
			ServerName: domain,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("HEAD", "https://"+domain+"/", nil)
	if err != nil {
		return "-"
	}
	req.Header.Set("User-Agent", "cf-checker/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "-"
	}
	defer resp.Body.Close()

	cfRay := resp.Header.Get("cf-ray")
	if cfRay == "" {
		return "-"
	}

	match := cfRayRegex.FindStringSubmatch(cfRay)
	if len(match) > 1 {
		return match[1]
	}
	return "-"
}

// ── Full domain test ─────────────────────────────────────────

func testDomain(idx int, domain, dnsServer string, ch chan<- resultMsg) {
	r := result{Domain: domain, Status: "testing"}

	// Notify start
	ch <- resultMsg{Index: idx, Result: r}

	// 1. Resolve: IPv6 priority
	ipv6 := dnsResolve(domain, dnsServer, dns.TypeAAAA)
	ipv4 := dnsResolve(domain, dnsServer, dns.TypeA)

	resolved := ""
	isIPv6 := false

	// Try IPv6 first with a quick ping
	if ipv6 != "" {
		testPing := doPing(ipv6)
		if testPing != "-" {
			resolved = ipv6
			isIPv6 = true
		}
	}

	// Fallback to IPv4
	if resolved == "" && ipv4 != "" {
		resolved = ipv4
		isIPv6 = false
	}

	if resolved == "" {
		r.Status = "error"
		r.IP = "NO RESOLVE"
		r.Ping1 = "-"
		r.Ping2 = "-"
		r.Node = "-"
		ch <- resultMsg{Index: idx, Result: r}
		return
	}

	r.IP = resolved
	r.IsIPv6 = isIPv6

	// 2. CF Node
	r.Node = getCFNode(domain, resolved, isIPv6)

	// 3. Two pings
	r.Ping1 = doPing(resolved)
	r.Ping2 = doPing(resolved)

	r.Status = "done"
	ch <- resultMsg{Index: idx, Result: r}
}

// ── Bubbletea Model ──────────────────────────────────────────

type model struct {
	results   []result
	dnsServer string
	total     int
	completed int
	startTime time.Time
	resultCh  chan resultMsg
	finished  bool
	quitting  bool
	scrollY   int
	width     int
	height    int
	tick      int
}

func initialModel(domains []string, dnsServer string) model {
	results := make([]result, len(domains))
	for i, d := range domains {
		results[i] = result{Domain: d, Status: "waiting"}
	}

	return model{
		results:   results,
		dnsServer: dnsServer,
		total:     len(domains),
		startTime: time.Now(),
		resultCh:  make(chan resultMsg, len(domains)*2),
		width:     100,
		height:    30,
	}
}

func (m model) Init() tea.Cmd {
	// Launch all goroutines
	go func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10) // Max 10 concurrent

		for i := range m.results {
			wg.Add(1)
			go func(idx int, domain string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				testDomain(idx, domain, m.dnsServer, m.resultCh)
			}(i, m.results[i].Domain)
		}

		wg.Wait()
		close(m.resultCh)
	}()

	return tea.Batch(
		waitForResult(m.resultCh),
		tickCmd(),
	)
}

func waitForResult(ch <-chan resultMsg) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return doneMsg{}
		}
		return r
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.scrollY > 0 {
				m.scrollY--
			}
		case "down", "j":
			maxScroll := m.total - m.visibleRows() + 1
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.scrollY < maxScroll {
				m.scrollY++
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case resultMsg:
		m.results[msg.Index] = msg.Result
		if msg.Result.Status == "done" || msg.Result.Status == "error" {
			m.completed++
		}
		if m.completed >= m.total {
			m.finished = true
		}
		return m, waitForResult(m.resultCh)

	case doneMsg:
		m.finished = true
		return m, tickCmd()

	case tickMsg:
		m.tick++
		if m.finished && m.quitting {
			return m, tea.Quit
		}
		return m, tickCmd()
	}

	return m, nil
}

func (m model) visibleRows() int {
	rows := m.height - 12
	if rows < 5 {
		rows = 5
	}
	return rows
}

// ── Render ────────────────────────────────────────────────────

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// Title
	titleW := m.width - 4
	if titleW < 60 {
		titleW = 60
	}
	title := titleStyle.Width(titleW).Render("CLOUDFLARE EDGE NODE CHECKER — SmartDist")
	b.WriteString(title + "\n")

	// Info line
	elapsed := time.Since(m.startTime).Truncate(100 * time.Millisecond)
	statusText := magentaStyle.Render("⚡ testing...")
	if m.finished {
		statusText = greenStyle.Render("✓ complete")
	}
	info := fmt.Sprintf(" DNS %s │ %d domains │ %s │ %s",
		cyanStyle.Render(m.dnsServer),
		m.total,
		dimStyle.Render(elapsed.String()),
		statusText,
	)
	b.WriteString(info + "\n\n")

	// Table header
	header := fmt.Sprintf(" %-34s %-20s %-10s %-10s %-6s",
		"DOMAIN", "IP", "PING #1", "PING #2", "NODE")
	b.WriteString(headerStyle.Render(header) + "\n")
	b.WriteString(dimStyle.Render(" "+strings.Repeat("─", 82)) + "\n")

	// Table rows
	vr := m.visibleRows()
	start := m.scrollY
	end := start + vr
	if end > m.total {
		end = m.total
	}

	for i := start; i < end; i++ {
		b.WriteString(m.renderRow(m.results[i]) + "\n")
	}

	// Padding
	rendered := end - start
	for rendered < vr {
		b.WriteString("\n")
		rendered++
	}

	// Progress bar
	b.WriteString("\n")
	progress := float64(m.completed) / float64(m.total)
	barW := 30
	filled := int(progress * float64(barW))
	bar := cyanStyle.Render(strings.Repeat("█", filled)) +
		dimStyle.Render(strings.Repeat("░", barW-filled))
	pctStr := fmt.Sprintf("%d/%d (%d%%)", m.completed, m.total, int(progress*100))
	b.WriteString(fmt.Sprintf(" %s %s\n", bar, pctStr))

	// Node summary
	nodes := make(map[string]int)
	for _, r := range m.results {
		if r.Status == "done" && r.Node != "" && r.Node != "-" {
			nodes[r.Node]++
		}
	}
	if len(nodes) > 0 {
		var parts []string
		keys := make([]string, 0, len(nodes))
		for k := range nodes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s (%d)", cyanStyle.Render(k), nodes[k]))
		}
		b.WriteString(" Nodes: " + strings.Join(parts, " │ ") + "\n")
	}

	// Keybindings
	hint := " q quit"
	if m.total > vr {
		hint = fmt.Sprintf(" ↑↓ scroll (%d-%d of %d) │ q quit", start+1, end, m.total)
	}
	b.WriteString(dimStyle.Render(hint) + "\n")

	return b.String()
}

func (m model) renderRow(r result) string {
	switch r.Status {
	case "waiting":
		return dimStyle.Render(fmt.Sprintf(" %-34s %-20s %-10s %-10s %-6s",
			r.Domain, "·", "·", "·", "·"))

	case "testing":
		spin := spinChars[m.tick%len(spinChars)]
		return fmt.Sprintf(" %-34s %s %s",
			r.Domain,
			yellowStyle.Render(spin+" testing..."),
			"")

	case "error":
		return fmt.Sprintf(" %-34s %-20s %-10s %-10s %-6s",
			r.Domain,
			redStyle.Render("NO RESOLVE"),
			dimStyle.Render("-"),
			dimStyle.Render("-"),
			dimStyle.Render("-"))

	case "done":
		// IP display (truncate if too long)
		ipDisplay := r.IP
		if len(ipDisplay) > 20 {
			ipDisplay = ipDisplay[:17] + "..."
		}

		// Color pings
		ping1 := colorPing(r.Ping1)
		ping2 := colorPing(r.Ping2)

		// Color node
		node := dimStyle.Render("-")
		if r.Node != "-" && r.Node != "" {
			node = cyanStyle.Render(r.Node)
		}

		return fmt.Sprintf(" %-34s %-20s %-10s %-10s %-6s",
			r.Domain, ipDisplay, ping1, ping2, node)
	}

	return ""
}

func colorPing(ms string) string {
	if ms == "-" || ms == "" {
		return dimStyle.Render("-")
	}

	// Parse value
	var val float64
	fmt.Sscanf(ms, "%f", &val)

	display := ms + "ms"
	if val < 30 {
		return greenStyle.Render(display)
	} else if val < 100 {
		return yellowStyle.Render(display)
	}
	return redStyle.Render(display)
}

// ── CLI ──────────────────────────────────────────────────────

func printHelp() {
	fmt.Println(`
Cloudflare Edge Node Checker — SmartDist Test Tool

Usage:
  cf-checker [options] [domain ...]

Options:
  --dns <ip>    DNS server to query (default: 127.0.0.1)
  --all         Use builtin domains + custom domains
  --builtin     Use builtin domains only (default if no domains given)
  --help, -h    Show this help

Examples:
  cf-checker                                 # 36 builtin domains
  cf-checker --dns 192.168.108.6             # builtin via DnsDist
  cf-checker --dns 192.168.108.6 my.com      # custom domain only
  cf-checker --dns 192.168.108.6 --all x.com # builtin + custom`)
	os.Exit(0)
}

func main() {
	dnsServer := "127.0.0.1"
	useBuiltin := false
	hasCustom := false
	var customDomains []string

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dns":
			if i+1 < len(args) {
				dnsServer = args[i+1]
				i++
			}
		case "--all":
			useBuiltin = true
		case "--builtin":
			useBuiltin = true
		case "--help", "-h":
			printHelp()
		default:
			customDomains = append(customDomains, args[i])
			hasCustom = true
		}
	}

	if !hasCustom {
		useBuiltin = true
	}

	var domains []string
	if useBuiltin {
		domains = append(domains, builtinDomains...)
	}
	domains = append(domains, customDomains...)

	if len(domains) == 0 {
		fmt.Println("No domains to test. Use --help for usage.")
		os.Exit(1)
	}

	m := initialModel(domains, dnsServer)
	p := tea.NewProgram(m, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
