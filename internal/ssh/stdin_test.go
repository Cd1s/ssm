package ssh

import "testing"

func forwardedText(value *bool) string {
	switch {
	case value == nil:
		return "unset"
	case *value:
		return "true"
	}
	return "false"
}

func TestDecideStdinRules(t *testing.T) {
	type input struct {
		mode    StdinMode
		file    string
		env     string
		capture bool
		tty     bool
		null    bool
	}
	for name, tc := range map[string]struct {
		in        input
		source    stdinSource
		forwarded string
		warning   bool
	}{
		"internal callers never forward":       {input{mode: StdinInternal, capture: true}, stdinNone, "unset", false},
		"internal ignores environment":         {input{mode: StdinInternal, env: "1"}, stdinNone, "unset", false},
		"human default non-tty forwards":       {input{mode: StdinDefault}, stdinPipe, "true", false},
		"human default null device forwards":   {input{mode: StdinDefault, null: true}, stdinPipe, "true", false},
		"human default tty is interactive":     {input{mode: StdinDefault, tty: true}, stdinTTY, "unset", false},
		"json default pipe reports false":      {input{mode: StdinDefault, capture: true}, stdinNone, "false", true},
		"json default tty is silent":           {input{mode: StdinDefault, capture: true, tty: true}, stdinNone, "unset", false},
		"json default null device is silent":   {input{mode: StdinDefault, capture: true, null: true}, stdinNone, "unset", false},
		"--stdin forwards json":                {input{mode: StdinForward, capture: true}, stdinPipe, "true", false},
		"--stdin forwards from tty":            {input{mode: StdinForward, tty: true}, stdinPipe, "true", false},
		"--no-stdin blocks human":              {input{mode: StdinDisable}, stdinNone, "unset", false},
		"--no-stdin json is silent":            {input{mode: StdinDisable, capture: true}, stdinNone, "unset", false},
		"env 1 forwards json":                  {input{mode: StdinDefault, env: "1", capture: true}, stdinPipe, "true", false},
		"env 0 blocks human":                   {input{mode: StdinDefault, env: "0"}, stdinNone, "unset", false},
		"env 0 json is silent":                 {input{mode: StdinDefault, env: "0", capture: true}, stdinNone, "unset", false},
		"other env values are ignored":         {input{mode: StdinDefault, env: "yes", capture: true}, stdinNone, "false", true},
		"--stdin beats env 0":                  {input{mode: StdinForward, env: "0"}, stdinPipe, "true", false},
		"--no-stdin beats env 1":               {input{mode: StdinDisable, env: "1"}, stdinNone, "unset", false},
		"stdin file forwards json":             {input{mode: StdinForward, file: "in", capture: true}, stdinFromFile, "true", false},
		"stdin file beats --no-stdin env 0":    {input{mode: StdinDefault, file: "in", env: "0"}, stdinFromFile, "true", false},
		"stdin file beats internal for direct": {input{mode: StdinInternal, file: "in"}, stdinFromFile, "true", false},
	} {
		t.Run(name, func(t *testing.T) {
			got := decideStdin(tc.in.mode, tc.in.file, tc.in.env, tc.in.capture, tc.in.tty, tc.in.null)
			if got.Source != tc.source || forwardedText(got.Forwarded) != tc.forwarded || (got.Warning != "") != tc.warning {
				t.Fatalf("decision = source %v forwarded %s warning %q; want source %v forwarded %s warning=%v",
					got.Source, forwardedText(got.Forwarded), got.Warning, tc.source, tc.forwarded, tc.warning)
			}
		})
	}
}

func TestDecideRunStdinScriptBodyOwnsStdin(t *testing.T) {
	got := decideRunStdin(RunOptions{Input: "true\n", Stdin: StdinForward, StdinFile: "in", Capture: true})
	if got.Source != stdinNone || got.Forwarded != nil || got.Warning != "" {
		t.Fatalf("script run decision = %+v, want none", got)
	}
}
