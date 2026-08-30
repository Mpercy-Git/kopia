package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUIPasswordFromFileGeneratesAndPersistsPassword(t *testing.T) {
	fname := filepath.Join(t.TempDir(), "subdir", defaultUIPasswordFileName)

	password, generated, err := uiPasswordFromFile(fname)
	require.NoError(t, err)
	require.True(t, generated)
	require.NotEmpty(t, password)

	stored, err := os.ReadFile(fname)
	require.NoError(t, err)
	require.Equal(t, password, strings.TrimSpace(string(stored)))

	if runtime.GOOS != "windows" {
		st, err := os.Stat(fname)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(uiPasswordFileMode), st.Mode().Perm())
	}

	// second invocation reuses the stored password.
	password2, generated2, err := uiPasswordFromFile(fname)
	require.NoError(t, err)
	require.False(t, generated2)
	require.Equal(t, password, password2)
}

func TestUIPasswordFromFileRegeneratesEmptyPassword(t *testing.T) {
	fname := filepath.Join(t.TempDir(), defaultUIPasswordFileName)

	require.NoError(t, os.WriteFile(fname, []byte("  \n"), uiPasswordFileMode))

	password, generated, err := uiPasswordFromFile(fname)
	require.NoError(t, err)
	require.True(t, generated)
	require.NotEmpty(t, password)
}

func TestUIPasswordFromFileUnreadableFile(t *testing.T) {
	dir := t.TempDir()

	// a directory in place of the password file cannot be read.
	_, _, err := uiPasswordFromFile(dir)
	require.Error(t, err)
}

func TestStartupBannerText(t *testing.T) {
	cases := []struct {
		name        string
		command     commandServerStart
		wantEmpty   bool
		wantStrings []string
		notWant     []string
	}{
		{
			name:      "no UI",
			command:   commandServerStart{},
			wantEmpty: true,
		},
		{
			name:        "UI without generated password",
			command:     commandServerStart{serverStartUI: true},
			wantStrings: []string{"http://localhost:51515", "http://localhost:51515/users"},
			notWant:     []string{"SERVER PASSWORD:", "No repository is connected"},
		},
		{
			name: "UI with generated password and no repository",
			command: commandServerStart{
				serverStartUI:            true,
				uiPassword:               "some-password",
				uiPasswordFile:           "/app/config/server-ui-password",
				uiPasswordGenerated:      true,
				startedWithoutRepository: true,
				sf:                       serverFlags{serverUsername: "kopia"},
			},
			wantStrings: []string{
				"SERVER USERNAME: kopia",
				"SERVER PASSWORD: some-password",
				"generated automatically and saved in /app/config/server-ui-password",
				"No repository is connected",
			},
		},
		{
			name: "UI with password from file",
			command: commandServerStart{
				serverStartUI:  true,
				uiPassword:     "some-password",
				uiPasswordFile: "/app/config/server-ui-password",
				sf:             serverFlags{serverUsername: "kopia"},
			},
			wantStrings: []string{"The password is stored in /app/config/server-ui-password"},
			notWant:     []string{"generated automatically", "No repository is connected"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.command.startupBannerText("http://localhost:51515")

			if tc.wantEmpty {
				require.Empty(t, got)
				return
			}

			for _, s := range tc.wantStrings {
				require.Contains(t, got, s)
			}

			for _, s := range tc.notWant {
				require.NotContains(t, got, s)
			}
		})
	}
}
