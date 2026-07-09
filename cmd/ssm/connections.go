package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/ssh"
	"ssm/internal/tui"
	"ssm/internal/vault"
)

type connectionJSON struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	User  string `json:"user"`
	Group string `json:"group,omitempty"`
}

func runList(jsonOutput bool) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	if jsonOutput {
		items := make([]connectionJSON, len(v.Connections))
		for i, c := range v.Connections {
			items[i] = connectionJSON{
				Name:  c.Name,
				Host:  c.Host,
				Port:  c.Port,
				User:  c.User,
				Group: c.Group,
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(items); err != nil {
			printError(err)
			os.Exit(1)
		}
		return
	}

	if len(v.Connections) == 0 {
		fmt.Println("No connections.")
		return
	}
	for _, c := range v.Connections {
		group := ""
		if c.Group != "" {
			group = " [" + c.Group + "]"
		}
		fmt.Printf("%s\t%s@%s:%d%s\n", c.Name, c.User, c.Host, c.Port, group)
	}
}

func runTUI() {
	mergeCloudVault()
	for {
		v, err := config.Load(masterPass)
		if err != nil {
			printError(err)
			os.Exit(1)
		}

		p := tea.NewProgram(tui.NewApp(v, masterPass), tea.WithAltScreen())
		result, err := p.Run()
		if err != nil {
			printError(err)
			os.Exit(1)
		}

		app := result.(tui.AppModel)
		if app.Result.Connect != nil {
			picker := func() *config.Connection {
				v2, _ := config.Load(masterPass)
				p2 := tea.NewProgram(tui.NewApp(v2, masterPass), tea.WithAltScreen())
				r2, err := p2.Run()
				if err != nil {
					return nil
				}
				a2 := r2.(tui.AppModel)
				return a2.Result.Connect
			}
			ssh.ConnectWithManager(*app.Result.Connect, app.Result.ConnectV, picker)
			continue
		}
		break
	}
}

func keyOptions() []string {
	v, _ := config.Load(masterPass)
	opts := []string{"(none)"}
	opts = append(opts, v.KeyNames()...)
	opts = append(opts, "+ Add new key")
	return opts
}

func runAdd() {
	fields := []tui.Field{
		{Label: "Name", Required: true},
		{Label: "Host", Required: true},
		{Label: "Port", Value: "22", Placeholder: "22"},
		{Label: "User", Required: true},
		{Label: "Password", Password: true},
		{Label: "Group"},
		{Label: "SSH Key", Value: "(none)", Options: keyOptions()},
	}

	p := tea.NewProgram(tui.NewFormModel("New connection", fields), tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		printError(err)
		return
	}

	fm := result.(tui.FormModel)
	if fm.Canceled || !fm.Done {
		return
	}

	name := fm.GetValue("Name")
	v, _ := config.Load(masterPass)
	for _, c := range v.Connections {
		if c.Name == name {
			fmt.Printf("Connection \"%s\" already exists.\n", name)
			return
		}
	}

	port, _ := strconv.Atoi(fm.GetValue("Port"))
	if port == 0 {
		port = 22
	}

	keyName := fm.GetValue("SSH Key")
	if keyName == "(none)" {
		keyName = ""
	}

	conn := config.Connection{
		Name:     name,
		Host:     fm.GetValue("Host"),
		Port:     port,
		User:     fm.GetValue("User"),
		Password: fm.GetValue("Password"),
		Group:    fm.GetValue("Group"),
		KeyName:  keyName,
	}

	v.Connections = append(v.Connections, conn)
	if err := config.Save(v, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}
	cloud.AutoPush()
	fmt.Printf("Connection \"%s\" added.\n", name)
}

func runRemove(name string) {
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	found := -1
	for i, c := range v.Connections {
		if c.Name == name {
			found = i
			break
		}
	}
	if found == -1 {
		fmt.Printf("Connection \"%s\" not found.\n", name)
		os.Exit(1)
	}

	v.Connections = append(v.Connections[:found], v.Connections[found+1:]...)
	if err := config.Save(v, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}
	cloud.AutoPush()
	fmt.Printf("Connection \"%s\" removed.\n", name)
}

func runExec(name, cmd string) {
	runExecSpec(name, remoteRunSpec{Command: cmd})
}

func runExecSpec(name string, spec remoteRunSpec) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, resolved, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	applyRunSpecEnv(spec)
	res := ssh.Run(c, v, ssh.RunOptions{
		Command:        spec.Command,
		Secrets:        spec.Secrets,
		Capture:        spec.JSON || spec.Plan,
		PlanOnly:       spec.Plan,
		NoReuse:        spec.NoReuse,
		RequestedAlias: name,
		ResolvedAlias:  resolved,
	})
	if spec.JSON || spec.Plan {
		ssh.WriteRunResult(res, spec.JSON)
		if spec.Plan {
			os.Exit(0)
		}
		if !res.OK {
			os.Exit(res.Exit)
		}
		os.Exit(0)
	}
	os.Exit(res.Exit)
}

func runMap(targetPatterns []string, spec remoteRunSpec) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	aliases, err := config.MatchAliases(v, targetPatterns)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	if len(aliases) == 0 {
		fmt.Fprintln(os.Stderr, "sshctl map: no targets matched")
		os.Exit(2)
	}
	applyRunSpecEnv(spec)
	workers := spec.Workers
	if workers <= 0 {
		workers = ssh.DefaultMapWorkers()
	}
	jobs := ssh.ExpandMapJobs(aliases, spec.Command, spec.Scripts, spec.Secrets)
	if len(jobs) == 0 {
		fmt.Fprintln(os.Stderr, "sshctl map: nothing to run")
		os.Exit(2)
	}
	if spec.Plan {
		// Plan: expand jobs and print without dialing.
		var planned []ssh.RunResult
		for _, j := range jobs {
			c, resolved, ok := resolveConnection(v, j.RequestedAlias)
			r := ssh.RunResult{
				OK:            true,
				Plan:          true,
				Alias:         j.RequestedAlias,
				ResolvedAlias: resolved,
				RemoteCommand: ssh.RedactSecrets(ssh.BuildRemoteCommand(j.Command, j.Secrets), j.Secrets),
				Risk:          ssh.AssessRisk(j.Command),
				ScriptLabel:   j.ScriptLabel,
			}
			if ok {
				r.User, r.Host, r.Port = c.User, c.Host, c.Port
				if r.Port == 0 {
					r.Port = 22
				}
			} else {
				r.OK = false
				r.Error = ssh.ErrCodeAliasNotFound
			}
			planned = append(planned, r)
		}
		ssh.WriteMapResults(planned, spec.JSON)
		os.Exit(0)
	}
	results := ssh.Map(v, jobs, workers, spec.NoReuse)
	ssh.WriteMapResults(results, spec.JSON)
	os.Exit(ssh.MapExitCode(results))
}

func runShell(name string) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, _, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	if err := ssh.ConnectInteractive(c, v); err != nil {
		printError(err)
		os.Exit(1)
	}
}

func runPut(name, localPath, remotePath string) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, _, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	if err := ssh.UploadPath(c, v, localPath, remotePath); err != nil {
		ssh.PrintAgentError(err, c)
		os.Exit(ssh.ExitCodeFor(err))
	}
}

func runGet(name, remotePath, localPath string) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, _, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	if err := ssh.DownloadPath(c, v, remotePath, localPath); err != nil {
		ssh.PrintAgentError(err, c)
		os.Exit(ssh.ExitCodeFor(err))
	}
}

func runCheck(name string, asJSON bool) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, resolved, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	res := ssh.Check(c, v)
	res.Alias = name
	if resolved != name {
		// keep host fields from connection; alias shows request name
	}
	ssh.WriteCheckResult(res, asJSON)
	if !res.OK {
		os.Exit(ssh.ExitConnectionFailed)
	}
}

func runDoctor(alias string, deep, asJSON bool) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	rep := ssh.Doctor(v, alias, deep)
	ssh.WriteDoctorReport(rep, asJSON)
	if !rep.OK {
		os.Exit(ssh.ExitConnectionFailed)
	}
}

func runRedirect(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: ssm redirect list|set <old> <new>|rm <old>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		r := config.LoadRedirects()
		if len(r) == 0 {
			fmt.Println("(no redirects)")
			return
		}
		// stable order
		var keys []string
		for k := range r {
			keys = append(keys, k)
		}
		// simple sort
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[j] < keys[i] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		for _, k := range keys {
			fmt.Printf("%s\t->\t%s\n", k, r[k])
		}
	case "set":
		if len(args) != 3 {
			fmt.Println("Usage: ssm redirect set <old-alias> <target-alias>")
			os.Exit(2)
		}
		r := config.LoadRedirects()
		r[args[1]] = args[2]
		if err := config.SaveRedirects(r); err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Printf("redirect %s -> %s\n", args[1], args[2])
	case "rm", "remove":
		if len(args) != 2 {
			fmt.Println("Usage: ssm redirect rm <old-alias>")
			os.Exit(2)
		}
		r := config.LoadRedirects()
		delete(r, args[1])
		if err := config.SaveRedirects(r); err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Printf("removed redirect %s\n", args[1])
	default:
		fmt.Println("Usage: ssm redirect list|set <old> <new>|rm <old>")
		os.Exit(2)
	}
}

func resolveConnection(v *config.Vault, name string) (config.Connection, string, bool) {
	return config.ResolveAlias(v, name)
}

func findConnection(v *config.Vault, name string) (config.Connection, bool) {
	c, _, ok := resolveConnection(v, name)
	return c, ok
}

func connectionNotFound(name string, v *config.Vault) {
	fmt.Fprintf(os.Stderr, "ssm: error=%s alias=%s\n", ssh.ErrCodeAliasNotFound, name)
	fmt.Fprintf(os.Stderr, "Connection %q not found.\n", name)
	if v != nil {
		names := make([]string, len(v.Connections))
		for i, c := range v.Connections {
			names[i] = c.Name
		}
		if sug := ssh.SuggestNames(name, names, 5); len(sug) > 0 {
			fmt.Fprintf(os.Stderr, "ssm: did_you_mean=%s\n", strings.Join(sug, ","))
			fmt.Fprintf(os.Stderr, "Did you mean: %s\n", strings.Join(sug, ", "))
		}
	}
	fmt.Fprintf(os.Stderr, "ssm: hint=use sshctl list --json; or ssm redirect set <old> <new> after migration\n")
	os.Exit(ssh.ExitConnectionFailed)
}

func runImportJSON(args []string) {
	opts, err := parseImportJSONArgs(args)
	if err != nil {
		printError(err)
		fmt.Println("Usage: ssm import-json <path> [--manifest <path>] [--expect-count <n>]")
		os.Exit(1)
	}

	imported, err := loadServerImport(opts.path, opts.manifestPath)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	if opts.expectCount > 0 && len(imported.Connections) != opts.expectCount {
		fmt.Fprintf(os.Stderr, "Error: imported host count %d does not match expected %d\n", len(imported.Connections), opts.expectCount)
		os.Exit(1)
	}

	current, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	if opts.replace {
		current.Connections = imported.Connections
		current.Keys = imported.Keys
	} else {
		current = config.MergeVaults(current, imported)
	}

	if err := config.Save(current, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}

	fmt.Printf("Imported %d connections and %d keys.\n", len(imported.Connections), len(imported.Keys))
}

type importJSONOptions struct {
	path         string
	manifestPath string
	expectCount  int
	replace      bool
}

func parseImportJSONArgs(args []string) (importJSONOptions, error) {
	opts := importJSONOptions{replace: true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--manifest":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--manifest requires a path")
			}
			opts.manifestPath = args[i+1]
			i++
		case strings.HasPrefix(arg, "--manifest="):
			opts.manifestPath = strings.TrimPrefix(arg, "--manifest=")
		case arg == "--expect-count":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--expect-count requires a number")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return opts, fmt.Errorf("--expect-count: %w", err)
			}
			if n < 0 {
				return opts, fmt.Errorf("--expect-count must be non-negative")
			}
			opts.expectCount = n
			i++
		case strings.HasPrefix(arg, "--expect-count="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--expect-count="))
			if err != nil {
				return opts, fmt.Errorf("--expect-count: %w", err)
			}
			if n < 0 {
				return opts, fmt.Errorf("--expect-count must be non-negative")
			}
			opts.expectCount = n
		case arg == "--replace":
			opts.replace = true
		case arg == "--replace=false":
			opts.replace = false
		case arg == "--merge":
			opts.replace = false
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown flag %s", arg)
		default:
			if opts.path != "" {
				return opts, fmt.Errorf("multiple import paths provided")
			}
			opts.path = arg
		}
	}
	if opts.path == "" {
		return opts, fmt.Errorf("import path required")
	}
	return opts, nil
}

func runEdit(name string) {
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	found := -1
	for i, c := range v.Connections {
		if c.Name == name {
			found = i
			break
		}
	}
	if found == -1 {
		fmt.Printf("Connection \"%s\" not found.\n", name)
		os.Exit(1)
	}

	c := v.Connections[found]
	keyVal := c.KeyName
	if keyVal == "" {
		keyVal = "(none)"
	}

	fields := []tui.Field{
		{Label: "Host", Value: c.Host, Required: true},
		{Label: "Port", Value: strconv.Itoa(c.Port), Placeholder: "22"},
		{Label: "User", Value: c.User, Required: true},
		{Label: "Password", Value: c.Password, Password: true},
		{Label: "Group", Value: c.Group},
		{Label: "SSH Key", Value: keyVal, Options: keyOptions()},
	}

	p := tea.NewProgram(tui.NewFormModel("Edit: "+name, fields), tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		printError(err)
		return
	}

	fm := result.(tui.FormModel)
	if fm.Canceled || !fm.Done {
		return
	}

	port, _ := strconv.Atoi(fm.GetValue("Port"))
	if port == 0 {
		port = 22
	}

	keyName := fm.GetValue("SSH Key")
	if keyName == "(none)" {
		keyName = ""
	}

	c.Host = fm.GetValue("Host")
	c.Port = port
	c.User = fm.GetValue("User")
	c.Password = fm.GetValue("Password")
	c.Group = fm.GetValue("Group")
	c.KeyName = keyName

	v.Connections[found] = c
	if err := config.Save(v, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}
	cloud.AutoPush()
	fmt.Printf("Connection \"%s\" updated.\n", name)
}

func mergeCloudVault() {
	settings := config.LoadSettings()
	if !settings.AutoSync {
		return
	}
	cfg, err := cloud.LoadCloud()
	if err != nil {
		return
	}

	localVault, _ := config.Load(masterPass)
	localBackup, _ := os.ReadFile(config.Path())

	if err := cloud.Pull(cfg); err != nil {
		config.Debug("merge: pull failed: %v", err)
		if config.Exists() && localBackup != nil {
			config.Debug("merge: no remote vault, pushing local")
			_ = cloud.Push(cfg)
		}
		return
	}

	remoteVault, err := config.Load(masterPass)
	if err == nil {
		config.Debug("merge: same password, merging vaults")
		merged := config.MergeVaults(localVault, remoteVault)
		_ = config.Save(merged, masterPass)
		cloud.AutoPush()
		return
	}

	if err != vault.ErrWrongPassword {
		config.Debug("merge: unexpected error: %v", err)
		_ = config.WritePrivateFile(config.Path(), localBackup)
		return
	}

	config.Debug("merge: different password, prompting user")
	for attempts := 0; attempts < 3; attempts++ {
		m := tui.NewUnlockModel(tui.UnlockCloudMerge)
		p := tea.NewProgram(m, tea.WithAltScreen())
		result, err := p.Run()
		if err != nil {
			_ = config.WritePrivateFile(config.Path(), localBackup)
			return
		}
		um := result.(tui.UnlockModel)
		if um.Canceled {
			config.Debug("merge: user cancelled")
			_ = config.WritePrivateFile(config.Path(), localBackup)
			return
		}

		remoteVault, err = config.Load(um.Password)
		if err == vault.ErrWrongPassword {
			continue
		}
		if err != nil {
			_ = config.WritePrivateFile(config.Path(), localBackup)
			return
		}

		config.Debug("merge: merging vaults with remote password")
		merged := config.MergeVaults(localVault, remoteVault)
		masterPass = um.Password
		_ = config.Save(merged, masterPass)
		if settings.PasswordCache == "session" {
			config.CachePassword(masterPass)
		}
		cloud.AutoPush()
		return
	}

	config.Debug("merge: 3 failed attempts, restoring local vault")
	_ = config.WritePrivateFile(config.Path(), localBackup)
}
