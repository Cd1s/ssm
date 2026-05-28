package ssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssm/internal/config"
)

type SSHSession struct {
	Name    string
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	buf     *RingBuffer
	done    chan struct{}
	closed  bool
}

type PickerFunc func() *config.Connection

type SessionManager struct {
	sessions []*SSHSession
	active   int
	mu       sync.Mutex
	width    int
	height   int
	vault    *config.Vault
	picker   PickerFunc
	quit     chan struct{}
	oldState *term.State
	running  bool
}

func NewSessionManager(v *config.Vault, picker PickerFunc) *SessionManager {
	w, h, _ := term.GetSize(int(os.Stdout.Fd()))
	return &SessionManager{
		vault:  v,
		picker: picker,
		width:  w,
		height: h,
		quit:   make(chan struct{}),
	}
}

func (m *SessionManager) clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func replayContent(data []byte) []byte {
	lastClear := -1
	for i := 0; i < len(data); i++ {
		if data[i] == '\033' && i+1 < len(data) && data[i+1] == '[' {
			j := i + 2
			for j < len(data) && ((data[j] >= '0' && data[j] <= '9') || data[j] == ';') {
				j++
			}
			if j < len(data) {
				seq := string(data[i+2 : j+1])
				if seq == "2J" || seq == "3J" {
					lastClear = j + 1
				}
			}
		}
	}
	if lastClear >= 0 {
		data = data[lastClear:]
	}
	return data
}

func (m *SessionManager) renderTabBar() {
	fmt.Print("\0337")
	fmt.Printf("\033[%d;1H", m.height)
	fmt.Print("\033[K")

	for i, s := range m.sessions {
		if i == m.active {
			fmt.Printf("\033[1;36m[%d: %s]\033[0m ", i+1, s.Name)
		} else {
			fmt.Printf("\033[90m[%d: %s]\033[0m ", i+1, s.Name)
		}
	}

	fmt.Print("\0338")
}

func (m *SessionManager) AddSession(c config.Connection, v *config.Vault) error {
	auth, err := buildAuth(c, v)
	if err != nil {
		return err
	}

	port := c.Port
	if port == 0 {
		port = 22
	}

	hostKeyCallback := buildHostKeyCallback()

	client, err := ssh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(port)), &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
	})
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return fmt.Errorf("session failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return err
	}

	session.Stderr = os.Stderr

	ptyH := m.height - 1
	if ptyH < 1 {
		ptyH = 1
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", ptyH, m.width, modes); err != nil {
		session.Close()
		client.Close()
		return fmt.Errorf("PTY: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return fmt.Errorf("shell: %w", err)
	}

	s := &SSHSession{
		Name:    c.Name,
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		buf:     &RingBuffer{},
		done:    make(chan struct{}),
	}

	m.mu.Lock()
	m.sessions = append(m.sessions, s)
	m.active = len(m.sessions) - 1
	if m.running {
		m.renderTabBar()
	}
	m.mu.Unlock()

	go m.readOutput(s)
	go m.waitSession(s)

	return nil
}

func (m *SessionManager) readOutput(s *SSHSession) {
	buf := make([]byte, 4096)
	for {
		n, err := s.stdout.Read(buf)
		if n > 0 {
			_, _ = s.buf.Write(buf[:n])

			m.mu.Lock()
			isActive := len(m.sessions) > 0 && m.active < len(m.sessions) && m.sessions[m.active] == s
			m.mu.Unlock()

			if isActive {
				os.Stdout.Write(buf[:n])
				m.mu.Lock()
				m.renderTabBar()
				m.mu.Unlock()
			}
		}
		if err != nil {
			return
		}
	}
}

func (m *SessionManager) waitSession(s *SSHSession) {
	_ = s.session.Wait()
	s.closed = true
	close(s.done)

	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	for i, sess := range m.sessions {
		if sess == s {
			idx = i
			break
		}
	}
	if idx == -1 {
		return
	}

	s.session.Close()
	s.client.Close()
	m.sessions = append(m.sessions[:idx], m.sessions[idx+1:]...)

	if len(m.sessions) == 0 {
		select {
		case <-m.quit:
		default:
			close(m.quit)
		}
		return
	}

	if m.active >= len(m.sessions) {
		m.active = len(m.sessions) - 1
	}

	m.clearScreen()
	buffered := replayContent(m.sessions[m.active].buf.Snapshot())
	if len(buffered) > 0 {
		os.Stdout.Write(buffered)
	}
	m.renderTabBar()
}

func (m *SessionManager) SwitchTo(idx int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if idx < 0 || idx >= len(m.sessions) || idx == m.active {
		return
	}

	m.active = idx
	m.clearScreen()
	buffered := replayContent(m.sessions[m.active].buf.Snapshot())
	if len(buffered) > 0 {
		os.Stdout.Write(buffered)
	}
	m.renderTabBar()
}

func (m *SessionManager) CloseActive() {
	m.mu.Lock()
	if len(m.sessions) == 0 {
		m.mu.Unlock()
		return
	}
	s := m.sessions[m.active]
	m.mu.Unlock()

	s.stdin.Close()
	s.session.Close()
}

func (m *SessionManager) resize() {
	w, h, _ := term.GetSize(int(os.Stdout.Fd()))
	m.mu.Lock()
	m.width = w
	m.height = h
	ptyH := h - 1
	if ptyH < 1 {
		ptyH = 1
	}
	for _, s := range m.sessions {
		if !s.closed {
			_ = s.session.WindowChange(ptyH, w)
		}
	}
	m.renderTabBar()
	m.mu.Unlock()
}

func (m *SessionManager) Start() error {
	var err error
	m.oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("terminal raw mode: %w", err)
	}
	m.running = true
	m.renderTabBar()
	return nil
}

func (m *SessionManager) Stop() {
	fmt.Print("\033[?1049l")
	_ = term.Restore(int(os.Stdin.Fd()), m.oldState)
	m.running = false
}

func (m *SessionManager) Run() {
	sigChan := make(chan os.Signal, 1)
	notifyResize(sigChan)
	go func() {
		for {
			select {
			case <-m.quit:
				return
			case <-sigChan:
				m.resize()
			}
		}
	}()

	go m.inputLoop()
	<-m.quit

	signal.Stop(sigChan)
	m.Stop()
}

func (m *SessionManager) inputLoop() {
	buf := make([]byte, 1)
	for {
		select {
		case <-m.quit:
			return
		default:
		}

		_, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}

		if buf[0] == 0x14 {
			// Wait for next byte (blocking - always reliable)
			_, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			// Ctrl+T Ctrl+T = forward a single Ctrl+T to SSH
			if buf[0] == 0x14 {
				m.forwardToActive([]byte{0x14})
			} else {
				m.handleCommand(buf[0])
			}
			continue
		}

		m.forwardToActive(buf)
	}
}

func (m *SessionManager) forwardToActive(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) > 0 && m.active < len(m.sessions) {
		_, _ = m.sessions[m.active].stdin.Write(data)
	}
}

func (m *SessionManager) handleCommand(cmd byte) {
	switch cmd {
	case 'n':
		m.openPicker()
	case 'w':
		m.CloseActive()
	case 'd':
		m.mu.Lock()
		for _, s := range m.sessions {
			if !s.closed {
				s.stdin.Close()
				s.session.Close()
				s.client.Close()
			}
		}
		m.sessions = nil
		m.mu.Unlock()
		select {
		case <-m.quit:
		default:
			close(m.quit)
		}
	default:
		if cmd >= '1' && cmd <= '9' {
			m.SwitchTo(int(cmd - '1'))
		} else {
			m.forwardToActive([]byte{0x14, cmd})
		}
	}
}

func (m *SessionManager) openPicker() {
	_ = term.Restore(int(os.Stdin.Fd()), m.oldState)
	fmt.Print("\033[2J\033[H")

	conn := m.picker()

	newState, _ := term.MakeRaw(int(os.Stdin.Fd()))
	m.oldState = newState

	added := false
	if conn != nil {
		if err := m.AddSession(*conn, m.vault); err != nil {
			fmt.Printf("\r\nError: %v\r\n", err)
			time.Sleep(time.Second)
		} else {
			added = true
		}
	}

	m.mu.Lock()
	if !added && len(m.sessions) > 0 {
		m.clearScreen()
		buffered := replayContent(m.sessions[m.active].buf.Snapshot())
		if len(buffered) > 0 {
			os.Stdout.Write(buffered)
		}
	}
	m.renderTabBar()
	m.mu.Unlock()
}
