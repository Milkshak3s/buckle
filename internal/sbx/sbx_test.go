package sbx

import (
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want ProfileSpec
	}{
		{"inline", []string{"/usr/bin/sandbox-exec", "-p", "(version 1)", "/bin/cat", "/etc/hosts"},
			ProfileSpec{Source: SourceInline, Inline: "(version 1)", Command: []string{"/bin/cat", "/etc/hosts"}}},
		{"file with param", []string{"/usr/bin/sandbox-exec", "-f", "/p.sb", "-D", "OUT=/private/tmp", "/usr/bin/touch", "x"},
			ProfileSpec{Source: SourceFile, File: "/p.sb", Params: [][2]string{{"OUT", "/private/tmp"}}, Command: []string{"/usr/bin/touch", "x"}}},
		{"named", []string{"/usr/bin/sandbox-exec", "-n", "no-network", "/usr/bin/curl", "-s"},
			ProfileSpec{Source: SourceNamed, Name: "no-network", Command: []string{"/usr/bin/curl", "-s"}}},
		{"attached and dashdash", []string{"sandbox-exec", "-pTEXT", "-DA=1", "-DNOVAL", "--", "/usr/bin/true"},
			ProfileSpec{Source: SourceInline, Inline: "TEXT", Params: [][2]string{{"A", "1"}, {"NOVAL", ""}}, Command: []string{"/usr/bin/true"}}},
		{"extra and clustered", []string{"sandbox-exec", "-d", "-t", "x", "-dp", "T", "cmd"},
			ProfileSpec{Source: SourceInline, Inline: "T", Extra: []string{"-d", "-t", "x", "-d"}, Command: []string{"cmd"}}},
		{"command options are not ours", []string{"sandbox-exec", "-p", "T", "/bin/ls", "-la", "-p", "Z"},
			ProfileSpec{Source: SourceInline, Inline: "T", Command: []string{"/bin/ls", "-la", "-p", "Z"}}},
		{"last profile option wins", []string{"sandbox-exec", "-n", "no-write", "-p", "T", "cmd"},
			ProfileSpec{Source: SourceInline, Inline: "T", Name: "no-write", Command: []string{"cmd"}}},
		{"no profile", []string{"sandbox-exec", "cmd"},
			ProfileSpec{Source: SourceUnknown, Command: []string{"cmd"}, Err: "no profile option"}},
		{"missing value", []string{"sandbox-exec", "-p"},
			ProfileSpec{Source: SourceUnknown, Err: "option -p requires a value"}},
		{"unknown option", []string{"sandbox-exec", "-z", "-p", "T", "cmd"},
			ProfileSpec{Source: SourceInline, Inline: "T", Extra: []string{"-z"}, Command: []string{"cmd"}}},
	}
	for _, c := range cases {
		got := ParseArgs(c.argv)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

func TestFindTag(t *testing.T) {
	profile := "(version 1)\n(allow default)\n; LogTag: CMD64_Y2F0IC9ldGMvaG9zdHMgfCBoZWFkIC0x_END__k3j9x0q2m_SBX\n" +
		`(deny file-read-data (literal "/private/etc/hosts") (with message "CMD64_Y2F0IC9ldGMvaG9zdHMgfCBoZWFkIC0x_END__k3j9x0q2m_SBX"))`
	tag, ok := FindTag(profile)
	if !ok {
		t.Fatal("tag not found")
	}
	want := Tag{
		Raw:        "CMD64_Y2F0IC9ldGMvaG9zdHMgfCBoZWFkIC0x_END__k3j9x0q2m_SBX",
		CommandB64: "Y2F0IC9ldGMvaG9zdHMgfCBoZWFkIC0x",
		Command:    "cat /etc/hosts | head -1",
		Suffix:     "_k3j9x0q2m_SBX",
	}
	if tag != want {
		t.Errorf("got %+v", tag)
	}

	tag, ok = FindTag("CMD64_!!notb64_END__abc_SBX")
	if ok {
		t.Errorf("non-base64 alphabet should not match: %+v", tag)
	}
	tag, ok = FindTag("x CMD64_Y2F_END__abc_SBX y")
	if !ok || tag.Command != "" || tag.Suffix != "_abc_SBX" {
		t.Errorf("undecodable base64: %+v %v", tag, ok)
	}
	if _, ok := FindTag("(version 1)(allow default)"); ok {
		t.Error("found tag in untagged profile")
	}
}
