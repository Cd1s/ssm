package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tickMsg time.Time

type CheckFunc func() bool

type VerifyModel struct {
	email    string
	check    CheckFunc
	verified bool
	dots     int
	width    int
	height   int
}

func NewVerifyModel(email string, check CheckFunc) VerifyModel {
	return VerifyModel{email: email, check: check}
}

func (m VerifyModel) Init() tea.Cmd {
	return tea.Batch(tickCmd(), checkCmd(m.check))
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type verifiedMsg struct{}

func checkCmd(check CheckFunc) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(3 * time.Second)
		if check() {
			return verifiedMsg{}
		}
		return checkAgainMsg{}
	}
}

type checkAgainMsg struct{}

func (m VerifyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.dots = (m.dots + 1) % 4
		return m, tickCmd()
	case verifiedMsg:
		m.verified = true
		return m, tea.Quit
	case checkAgainMsg:
		return m, checkCmd(m.check)
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m VerifyModel) View() string {
	var content strings.Builder

	content.WriteString(titleStyle.Render("  ~ ssm"))
	content.WriteString("\n\n")

	if m.verified {
		content.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E")).Bold(true).Render("  Email verified!"))
		content.WriteString("\n\n")
		content.WriteString(dimRow.Render("  Your account is ready. You can now use ssm push and ssm pull."))
	} else {
		content.WriteString(normalRow.Render("  Verification email sent to:"))
		content.WriteString("\n")
		content.WriteString(selectedRow.Render("  " + m.email))
		content.WriteString("\n\n")
		dots := strings.Repeat(".", m.dots+1) + strings.Repeat(" ", 3-m.dots)
		content.WriteString(dimRow.Render("  Waiting for verification" + dots))
		content.WriteString("\n\n")
		content.WriteString(dimRow.Render("  Check your inbox and click the verification link."))
	}

	content.WriteString("\n")
	if !m.verified {
		content.WriteString(footerBar(
			footerItem("q", "quit"),
		))
	}

	out := lipgloss.NewStyle().Padding(1, 3).Render(content.String())
	if m.width > 0 {
		return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, out)
	}
	return out
}

func (m VerifyModel) Verified() bool {
	return m.verified
}
