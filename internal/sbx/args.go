// Package sbx understands sandbox-exec command lines and Claude Code sandbox tags.
package sbx

import "strings"

const SandboxExecPath = "/usr/bin/sandbox-exec"

type ProfileSource string

const (
	SourceInline  ProfileSource = "inline"
	SourceFile    ProfileSource = "file"
	SourceNamed   ProfileSource = "named"
	SourceUnknown ProfileSource = "unknown"
)

// ProfileSpec is what a sandbox-exec argv says about its profile and target command.
type ProfileSpec struct {
	Source  ProfileSource
	Inline  string
	File    string
	Name    string
	Params  [][2]string // -D key=value, in order
	Extra   []string    // other options (-d, -e X, -t X, unknown), raw
	Command []string    // argv after the options
	Err     string
}

// ParseArgs parses argv (argv[0] is sandbox-exec) with getopt semantics for "D:de:f:n:p:t:".
// Only a missing profile option or a missing option value is reported in Err.
func ParseArgs(argv []string) ProfileSpec {
	s := ProfileSpec{Source: SourceUnknown}
	i := 1
args:
	for ; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			i++
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			break
		}
		for j := 1; j < len(arg); j++ {
			c := arg[j]
			switch c {
			case 'd':
				s.Extra = append(s.Extra, "-d")
			case 'D', 'e', 'f', 'n', 'p', 't':
				val := arg[j+1:]
				if val == "" {
					if i+1 >= len(argv) {
						s.Source = SourceUnknown
						s.Err = "option -" + string(c) + " requires a value"
						return s
					}
					i++
					val = argv[i]
				}
				s.apply(c, val)
				continue args
			default:
				s.Extra = append(s.Extra, "-"+string(c))
			}
		}
	}
	if i < len(argv) {
		s.Command = append([]string(nil), argv[i:]...)
	}
	if s.Source == SourceUnknown {
		s.Err = "no profile option"
	}
	return s
}

func (s *ProfileSpec) apply(opt byte, val string) {
	switch opt {
	case 'D':
		k, v, _ := strings.Cut(val, "=")
		s.Params = append(s.Params, [2]string{k, v})
	case 'f':
		s.Source, s.File = SourceFile, val
	case 'n':
		s.Source, s.Name = SourceNamed, val
	case 'p':
		s.Source, s.Inline = SourceInline, val
	default:
		s.Extra = append(s.Extra, "-"+string(opt), val)
	}
}
