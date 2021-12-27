package googleoauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/alesr/callbacksrv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v2"
)

var (
	// Enumerate initialization errors

	ErrMissingCredentialsPath = errors.New("missing credentials path")
	ErrMissingRedirectURL     = errors.New("missing redirect url")
)

func New(httpCli *http.Client, tokenCh chan string, credentialsPath, redirectURL string) (*http.Client, error) {
	if credentialsPath == "" {
		return nil, ErrMissingCredentialsPath
	}

	if redirectURL == "" {
		return nil, ErrMissingRedirectURL
	}

	b, err := ioutil.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("could not read file credentials file: %s", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, drive.DriveScope)
	if err != nil {
		return nil, fmt.Errorf("could not parse client secret file to config: %s", err)
	}

	config.RedirectURL = redirectURL

	client, err := getClient(config)
	if err != nil {
		return nil, fmt.Errorf("could not get authenticated client: %s", err)
	}

	return client, nil
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) (*http.Client, error) {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok, err = getTokenFromWeb(config)
		if err != nil {
			return nil, fmt.Errorf("could not get token from web: %s", err)
		}

		if err := saveToken(tokFile, tok); err != nil {
			return nil, fmt.Errorf("could not save web token: %s", err)
		}
	}
	return config.Client(context.Background(), tok), nil
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	notifyCh := make(chan struct{}, 1)
	quitCh := make(chan os.Signal, 1)

	codeCh := make(chan string, 1)
	opt := callbacksrv.WithCodeChan(codeCh)

	go callbacksrv.Serve(notifyCh, quitCh, opt)

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n\n%s\n\n", authURL)

	<-notifyCh
	authCode := <-codeCh
	quitCh <- os.Interrupt

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve token from web: %s", err)
	}
	return tok, nil
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("could not cache oauth token: %s", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(token); err != nil {
		return fmt.Errorf("could not decode token: %s", err)
	}
	return nil
}
