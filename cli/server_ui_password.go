package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

const (
	// defaultUIPasswordFileName is the name of the file, stored next to the repository
	// configuration file, which holds the automatically-generated server UI password.
	defaultUIPasswordFileName = "server-ui-password"

	uiPasswordFileMode = 0o600
	uiPasswordDirMode  = 0o700
)

// uiPasswordFromFile returns the server UI password stored in the provided file, generating
// and persisting a new random password when the file does not exist or is empty.
// It also reports whether a new password had to be generated.
func uiPasswordFromFile(fname string) (password string, generated bool, err error) {
	//nolint:gosec // the path comes from the server administrator, not from user input
	switch b, rerr := os.ReadFile(fname); {
	case rerr == nil:
		if p := strings.TrimSpace(string(b)); p != "" {
			return p, false, nil
		}

	case !os.IsNotExist(rerr):
		return "", false, errors.Wrapf(rerr, "unable to read UI password file %v", fname)
	}

	password = rand.Text()

	if derr := os.MkdirAll(filepath.Dir(fname), uiPasswordDirMode); derr != nil {
		return "", false, errors.Wrapf(derr, "unable to create directory for UI password file %v", fname)
	}

	if werr := os.WriteFile(fname, []byte(password+"\n"), uiPasswordFileMode); werr != nil {
		return "", false, errors.Wrapf(werr, "unable to write UI password file %v", fname)
	}

	return password, true, nil
}
