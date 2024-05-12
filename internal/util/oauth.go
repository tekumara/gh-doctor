// Adapted from https://github.com/hickford/git-credential-oauth/blob/78216c942fe2ba205ba6ad4d2ad7fa064b5c6466/main.go#L380
// with modifications to simplify the code to only fetch a token for GitHub.

package util

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var (
	config = oauth2.Config{
		// https://github.com/settings/applications/2575367
		ClientID: "Ov23liukLtggLaIpvb2o",
		// This secret is not confidential and can be shipped with the app.
		// This is expected for installed OAuth apps which (unlike web apps) are public clients
		// "It is assumed that any client authentication credentials included in the application can be extracted"
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
		ClientSecret: "4916902e0ccc6ad9074063aca1e3e26532047751",
		Endpoint:     endpoints.GitHub,
		Scopes: []string{"admin:public_key"},
	}
)

var html string = `<!DOCTYPE html>
<html lang="en">
<head>
	<title>Github Doctor authentication success</title>
</head>
<body>
<p>Success. Github Doctor has authenticated. You may close this page.</p>
<p style="font-style: italic">&mdash;<a href="https://github.com/tekumara/gh-doctor">gh-doctor</a></p>
</body>
</html>`

func FetchToken(ctx context.Context) (*oauth2.Token, error) {
	state := oauth2.GenerateVerifier()
	queries := make(chan url.Values)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: consider whether to show errors in browser or command line
		queries <- r.URL.Query()
		w.Header().Add("Content-Type", "text/html")
		w.Write([]byte(html))
	})
	var server *httptest.Server
	c := config
	server = httptest.NewServer(handler)
	c.RedirectURL = server.URL
	defer server.Close()

	verifier := oauth2.GenerateVerifier()
	authCodeURL := c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n%s\n", authCodeURL)
	var open string
	switch runtime.GOOS {
	case "windows":
		open = "start"
	case "darwin":
		open = "open"
	default:
		open = "xdg-open"
	}
	// TODO: wait for server to start before opening browser
	if _, err := exec.LookPath(open); err == nil {
		err = exec.Command(open, authCodeURL).Run()
		if err != nil {
			return nil, err
		}
	}
	query := <-queries
	server.Close()
	if query.Get("state") != state {
		return nil, fmt.Errorf("state mismatch")
	}
	code := query.Get("code")
	return c.Exchange(ctx, code, oauth2.VerifierOption(verifier))
}
