package server_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kopia/kopia/internal/apiclient"
	"github.com/kopia/kopia/internal/repotesting"
	"github.com/kopia/kopia/internal/server"
	"github.com/kopia/kopia/internal/serverapi"
	"github.com/kopia/kopia/internal/servertesting"
	"github.com/kopia/kopia/internal/user"
)

func startServerWithUIClient(t *testing.T) (context.Context, *apiclient.KopiaAPIClient, *repotesting.Environment) {
	t.Helper()

	ctx, env := repotesting.NewEnvironment(t, repotesting.FormatNotImportant)
	srvInfo := servertesting.StartServerContext(ctx, t, env, false)

	cli, err := apiclient.NewKopiaAPIClient(apiclient.Options{
		BaseURL:                             srvInfo.BaseURL,
		TrustedServerCertificateFingerprint: srvInfo.TrustedServerCertificateFingerprint,
		Username:                            servertesting.TestUIUsername,
		Password:                            servertesting.TestUIPassword,
	})
	require.NoError(t, err)
	require.NoError(t, cli.FetchCSRFTokenForTesting(ctx))

	return ctx, cli, env
}

func TestRepositoryUsersLifecycle(t *testing.T) {
	ctx, cli, env := startServerWithUIClient(t)

	users, err := serverapi.ListRepositoryUsers(ctx, cli)
	require.NoError(t, err)
	require.Empty(t, users.Users)

	require.NoError(t, serverapi.CreateRepositoryUser(ctx, cli, &serverapi.CreateRepositoryUserRequest{
		Username: "alice@laptop",
		Password: "some-password",
	}))

	require.NoError(t, serverapi.CreateRepositoryUser(ctx, cli, &serverapi.CreateRepositoryUserRequest{
		Username: "bob@desktop",
		Password: "another-password",
	}))

	users, err = serverapi.ListRepositoryUsers(ctx, cli)
	require.NoError(t, err)
	require.Equal(t, []serverapi.RepositoryUser{
		{Username: "alice@laptop"},
		{Username: "bob@desktop"},
	}, users.Users)

	// the password set through the API is the one stored in the repository.
	p, err := user.GetUserProfile(ctx, env.Repository, "alice@laptop")
	require.NoError(t, err)

	valid, err := p.IsValidPassword("some-password")
	require.NoError(t, err)
	require.True(t, valid)

	require.NoError(t, serverapi.SetRepositoryUserPassword(ctx, cli, "alice@laptop", &serverapi.SetRepositoryUserPasswordRequest{
		Password: "changed-password",
	}))

	p, err = user.GetUserProfile(ctx, env.Repository, "alice@laptop")
	require.NoError(t, err)

	valid, err = p.IsValidPassword("changed-password")
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = p.IsValidPassword("some-password")
	require.NoError(t, err)
	require.False(t, valid)

	require.NoError(t, serverapi.DeleteRepositoryUser(ctx, cli, "alice@laptop"))

	users, err = serverapi.ListRepositoryUsers(ctx, cli)
	require.NoError(t, err)
	require.Equal(t, []serverapi.RepositoryUser{{Username: "bob@desktop"}}, users.Users)

	_, err = user.GetUserProfile(ctx, env.Repository, "alice@laptop")
	require.ErrorIs(t, err, user.ErrUserNotFound)
}

func TestRepositoryUsersInvalidRequests(t *testing.T) {
	ctx, cli, _ := startServerWithUIClient(t)

	cases := []struct {
		name           string
		req            *serverapi.CreateRepositoryUserRequest
		wantErrMessage string
	}{
		{
			name:           "missing username",
			req:            &serverapi.CreateRepositoryUserRequest{Password: "some-password"},
			wantErrMessage: "username is required",
		},
		{
			name:           "username without hostname",
			req:            &serverapi.CreateRepositoryUserRequest{Username: "alice", Password: "some-password"},
			wantErrMessage: "username must be specified as lowercase 'user@hostname'",
		},
		{
			name:           "missing password",
			req:            &serverapi.CreateRepositoryUserRequest{Username: "alice@laptop"},
			wantErrMessage: "password is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := serverapi.CreateRepositoryUser(ctx, cli, tc.req)
			require.ErrorContains(t, err, tc.wantErrMessage)
		})
	}
}

func TestRepositoryUsersDuplicateAndMissing(t *testing.T) {
	ctx, cli, _ := startServerWithUIClient(t)

	require.NoError(t, serverapi.CreateRepositoryUser(ctx, cli, &serverapi.CreateRepositoryUserRequest{
		Username: "alice@laptop",
		Password: "some-password",
	}))

	err := serverapi.CreateRepositoryUser(ctx, cli, &serverapi.CreateRepositoryUserRequest{
		Username: "alice@laptop",
		Password: "some-password",
	})
	require.ErrorContains(t, err, "user already exists")

	err = serverapi.SetRepositoryUserPassword(ctx, cli, "nobody@laptop", &serverapi.SetRepositoryUserPasswordRequest{
		Password: "some-password",
	})
	requireHTTPStatus(t, err, http.StatusNotFound)

	err = serverapi.DeleteRepositoryUser(ctx, cli, "nobody@laptop")
	requireHTTPStatus(t, err, http.StatusNotFound)
}

func TestRepositoryUsersRequireUIUser(t *testing.T) {
	ctx, env := repotesting.NewEnvironment(t, repotesting.FormatNotImportant)
	srvInfo := servertesting.StartServerContext(ctx, t, env, false)

	uiCli, err := apiclient.NewKopiaAPIClient(apiclient.Options{
		BaseURL:                             srvInfo.BaseURL,
		TrustedServerCertificateFingerprint: srvInfo.TrustedServerCertificateFingerprint,
		Username:                            servertesting.TestUIUsername,
		Password:                            servertesting.TestUIPassword,
	})
	require.NoError(t, err)
	require.NoError(t, uiCli.FetchCSRFTokenForTesting(ctx))

	// a repository user is authenticated, but is not allowed to manage user accounts.
	cli, err := apiclient.NewKopiaAPIClient(apiclient.Options{
		BaseURL:                             srvInfo.BaseURL,
		TrustedServerCertificateFingerprint: srvInfo.TrustedServerCertificateFingerprint,
		Username:                            servertesting.TestUsername + "@" + servertesting.TestHostname,
		Password:                            servertesting.TestPassword,
	})
	require.NoError(t, err)

	// the repository user cannot get a session of its own, borrow the one from the UI user
	// to make sure the request fails authorization and not the CSRF token check.
	cli.HTTPClient.Jar = uiCli.HTTPClient.Jar
	cli.CSRFToken = uiCli.CSRFToken

	_, err = serverapi.ListRepositoryUsers(ctx, cli)
	requireHTTPStatus(t, err, http.StatusForbidden)

	err = serverapi.CreateRepositoryUser(ctx, cli, &serverapi.CreateRepositoryUserRequest{
		Username: "alice@laptop",
		Password: "some-password",
	})
	requireHTTPStatus(t, err, http.StatusForbidden)
}

func requireHTTPStatus(t *testing.T, err error, want int) {
	t.Helper()

	var hs apiclient.HTTPStatusError

	require.ErrorAs(t, err, &hs)
	require.Equal(t, want, hs.HTTPStatusCode)
}

func TestUsersPageIsServedToUIUser(t *testing.T) {
	ctx, cli, _ := startServerWithUIClient(t)

	var page []byte

	require.NoError(t, cli.Get(ctx, server.UsersPagePath, nil, &page))

	// the page carries the CSRF token needed to call the user management API.
	require.Contains(t, string(page), `<meta name="kopia-csrf-token"`)
	require.Contains(t, string(page), "/api/v1/users")
}

func TestUsersPageRequiresUIUser(t *testing.T) {
	ctx, env := repotesting.NewEnvironment(t, repotesting.FormatNotImportant)
	srvInfo := servertesting.StartServerContext(ctx, t, env, false)

	cli, err := apiclient.NewKopiaAPIClient(apiclient.Options{
		BaseURL:                             srvInfo.BaseURL,
		TrustedServerCertificateFingerprint: srvInfo.TrustedServerCertificateFingerprint,
		Username:                            servertesting.TestUsername + "@" + servertesting.TestHostname,
		Password:                            servertesting.TestPassword,
	})
	require.NoError(t, err)

	var page []byte

	requireHTTPStatus(t, cli.Get(ctx, server.UsersPagePath, nil, &page), http.StatusForbidden)
}
