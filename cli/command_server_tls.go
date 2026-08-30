package cli

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/pkg/errors"

	"github.com/kopia/kopia/internal/insecureserverbind"
	"github.com/kopia/kopia/internal/tlsutil"
)

const (
	oneDay = 24 * time.Hour

	// width of the separator line in the server startup banner.
	bannerWidth = 80
)

func (c *commandServerStart) generateServerCertificate(ctx context.Context) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, key, err := tlsutil.GenerateServerCertificate(
		ctx,
		c.serverStartTLSGenerateRSAKeySize,
		time.Duration(c.serverStartTLSGenerateCertValidDays)*oneDay,
		c.serverStartTLSGenerateCertNames)

	return cert, key, errors.Wrap(err, "error generating server certificate")
}

func (c *commandServerStart) startServerWithOptionalTLS(ctx context.Context, httpServer *http.Server) error {
	var l net.Listener

	var err error

	listeners, err := activation.Listeners()
	if err != nil {
		return errors.Wrap(err, "socket-activation error")
	}

	switch len(listeners) {
	case 0:
		if after, ok := strings.CutPrefix(httpServer.Addr, "unix:"); ok {
			l, err = (&net.ListenConfig{}).Listen(ctx, "unix", after)
		} else {
			l, err = (&net.ListenConfig{}).Listen(ctx, "tcp", httpServer.Addr)
		}

		if err != nil {
			return errors.Wrap(err, "listen error")
		}
	case 1:
		l = listeners[0]
	default:
		return errors.Errorf("Too many activated sockets found.  Expected 1, got %v", len(listeners))
	}

	if err := insecureserverbind.ValidateListenerAddrIfRestricted(
		c.serverStartInsecure,
		c.serverStartWithoutPassword,
		c.serverStartAllowDangerousUnauthenticatedNetwork,
		l.Addr(),
	); err != nil {
		l.Close() //nolint:errcheck

		return errors.Wrap(err, "insecure server bind validation")
	}

	defer l.Close() //nolint:errcheck

	httpServer.Addr = l.Addr().String()

	return c.startServerWithOptionalTLSAndListener(ctx, httpServer, l)
}

func (c *commandServerStart) maybeGenerateTLS(ctx context.Context) error {
	if !c.serverStartTLSGenerateCert || c.serverStartTLSCertFile == "" || c.serverStartTLSKeyFile == "" {
		return nil
	}

	if _, err := os.Stat(c.serverStartTLSCertFile); err == nil {
		return errors.Errorf("TLS cert file already exists: %q", c.serverStartTLSCertFile)
	}

	if _, err := os.Stat(c.serverStartTLSKeyFile); err == nil {
		return errors.Errorf("TLS key file already exists: %q", c.serverStartTLSKeyFile)
	}

	cert, key, err := c.generateServerCertificate(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to generate server cert")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fmt.Fprintf(c.out.stderr(), "SERVER CERT SHA256: %v\n", hex.EncodeToString(fingerprint[:])) //nolint:errcheck

	log(ctx).Infof("writing TLS certificate to %v", c.serverStartTLSCertFile)

	if err := tlsutil.WriteCertificateToFile(c.serverStartTLSCertFile, cert); err != nil {
		return errors.Wrap(err, "unable to write private key")
	}

	log(ctx).Infof("writing TLS private key to %v", c.serverStartTLSKeyFile)

	if err := tlsutil.WritePrivateKeyToFile(c.serverStartTLSKeyFile, key); err != nil {
		return errors.Wrap(err, "unable to write private key")
	}

	return nil
}

func (c *commandServerStart) startServerWithOptionalTLSAndListener(ctx context.Context, httpServer *http.Server, listener net.Listener) error {
	if err := c.maybeGenerateTLS(ctx); err != nil {
		return err
	}

	udsPfx := ""
	if listener.Addr().Network() == "unix" {
		udsPfx = "unix+"
	}

	switch {
	case c.serverStartTLSCertFile != "" && c.serverStartTLSKeyFile != "":
		// PEM files provided
		c.showServerAddressAndStartupBanner(fmt.Sprintf("%shttps://%v", udsPfx, httpServer.Addr))

		return checkErrServerClosed(ctx, httpServer.ServeTLS(listener, c.serverStartTLSCertFile, c.serverStartTLSKeyFile), "error starting TLS server")

	case c.serverStartTLSGenerateCert:
		// PEM files not provided, generate in-memory TLS cert/key but don't persist.
		cert, key, err := c.generateServerCertificate(ctx)
		if err != nil {
			return errors.Wrap(err, "unable to generate server cert")
		}

		httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
				},
			},
		}

		fingerprint := sha256.Sum256(cert.Raw)
		fmt.Fprintf(c.out.stderr(), "SERVER CERT SHA256: %v\n", hex.EncodeToString(fingerprint[:])) //nolint:errcheck

		if c.serverStartTLSPrintFullServerCert {
			// dump PEM-encoded server cert, only used by KopiaUI to securely connect.
			var b bytes.Buffer

			if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
				return errors.Wrap(err, "Failed to write data")
			}

			fmt.Fprintf(c.out.stderr(), "SERVER CERTIFICATE: %v\n", base64.StdEncoding.EncodeToString(b.Bytes())) //nolint:errcheck
		}

		c.showServerAddressAndStartupBanner(fmt.Sprintf("%shttps://%v", udsPfx, httpServer.Addr))

		return checkErrServerClosed(ctx, httpServer.ServeTLS(listener, "", ""), "error starting TLS server")

	default:
		if !c.serverStartInsecure {
			return errors.New("TLS not configured. To start server without encryption pass --insecure")
		}

		c.showServerAddressAndStartupBanner(fmt.Sprintf("%shttp://%v", udsPfx, httpServer.Addr))

		return checkErrServerClosed(ctx, httpServer.Serve(listener), "error starting server")
	}
}

// showServerAddressAndStartupBanner prints a banner telling the user how to start using the UI,
// followed by the address the server is listening on. The address is printed last because tools
// launching the server (such as KopiaUI) treat it as the last line of the startup preamble.
func (c *commandServerStart) showServerAddressAndStartupBanner(url string) {
	fmt.Fprint(c.out.stderr(), c.startupBannerText(url)+"SERVER ADDRESS: "+url+"\n") //nolint:errcheck
}

// startupBannerText returns human-readable instructions printed when the server starts,
// including auto-generated UI credentials, if any.
func (c *commandServerStart) startupBannerText(url string) string {
	if !c.serverStartUI {
		return ""
	}

	var b strings.Builder

	separator := strings.Repeat("=", bannerWidth) + "\n"

	b.WriteString(separator)
	b.WriteString("Open " + url + " in a web browser to use the Kopia UI.\n")

	if c.uiPassword != "" {
		b.WriteString("\nLog in with the following credentials:\n\n")
		b.WriteString("SERVER USERNAME: " + c.sf.serverUsername + "\n")
		b.WriteString("SERVER PASSWORD: " + c.uiPassword + "\n")

		if c.uiPasswordGenerated {
			b.WriteString("\nThe password was generated automatically and saved in " + c.uiPasswordFile + "\n")
		} else {
			b.WriteString("\nThe password is stored in " + c.uiPasswordFile + "\n")
		}

		b.WriteString("To use a password of your choice instead, set the KOPIA_SERVER_PASSWORD environment\n")
		b.WriteString("variable or pass --server-password when starting the server.\n")
	}

	if c.startedWithoutRepository {
		b.WriteString("\nNo repository is connected yet - the UI will guide you through creating a new\n")
		b.WriteString("repository or connecting to an existing one.\n")
	}

	b.WriteString(separator)

	return b.String()
}

func checkErrServerClosed(ctx context.Context, err error, msg string) error {
	if errors.Is(err, http.ErrServerClosed) {
		log(ctx).Debug("HTTP server closed:", err)

		return nil
	}

	return errors.Wrap(err, msg)
}
