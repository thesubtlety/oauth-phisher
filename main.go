package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type OAuthResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Code             string `json:"code"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type OAuthCode struct {
	GrantType    string `json:"grant_type"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
}

var port string
var clientId string
var clientSecret string
var redirectURI string
var certfile string
var keyfile string
var callbackPath string
var oauthURL string
var apiURL string
var redirURL string
var userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/600.8.9 (KHTML, like Gecko)"

var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
var Usage = func() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {

	flag.StringVar(&port, "port", "443", "port to serve on")
	flag.StringVar(&clientId, "client-id", "", " ClientID")
	flag.StringVar(&clientSecret, "client-secret", "", " Client Secret")
	flag.StringVar(&redirectURI, "redirect-uri", "", " Redirect URL")
	flag.StringVar(&certfile, "cert", "", "path to cert file")
	flag.StringVar(&keyfile, "key", "", "path to key file")
	flag.StringVar(&oauthURL, "oauth", "https://github.com/login/oauth/access_token", "oauth access token endpoint")
	flag.StringVar(&apiURL, "api", "https://api.github.com", "API URL")
	flag.StringVar(&redirURL, "redir", "https://github.com", "where to send the user after adding the oauth app")
	flag.StringVar(&callbackPath, "callback-path", "/callback", "app callback path")
	flag.Parse()

	// Wait for callback from client
	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		url := r.RequestURI
		state := r.FormValue("state")
		code := r.FormValue("code")
		ip := r.RemoteAddr
		userAgent := r.UserAgent()
		log.Printf("%s\t%s\t%s\tstate=%s\n", ip, userAgent, url, state)

		//Thanks and goodbye, user
		w.Header().Set("Location", redirURL)
		w.WriteHeader(http.StatusFound)

		exchangeCodeForJWT(code)
	})

	log.Printf("Starting HTTP server at %q", "0.0.0.0:"+port)
	if certfile != "" {
		log.Fatal(http.ListenAndServeTLS("0.0.0.0:"+port, certfile, keyfile, nil))
	}
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}

func exchangeCodeForJWT(code string) {
	log.Printf("Exchanging code for JWT")
	httpClient := http.Client{}

	// Exchange code for JWT token
	data := OAuthCode{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
	}
	//fmt.Printf("%+v\n", data)
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(data)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, oauthURL, &buf)
	if err != nil {
		log.Printf("could not create HTTP request: %v", err)
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", userAgent)
	res, err := httpClient.Do(req)
	if err != nil {
		log.Printf("could not send HTTP request: %v", err)
		return
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Exchange response\n\t%s\n", string(bytes))

	var auth OAuthResponse
	if err := json.Unmarshal(bytes, &auth); err != nil {
		log.Printf("could not parse JSON response: %v", err)
		return
	}

	if auth.AccessToken == "" {
		log.Printf("Missing access token in response")
		return
	}
	getAPIUser(auth)
}

func getAPIUser(jwt OAuthResponse) {
	res := "/user"
	fmt.Printf("%+v\n", apiURL+res)
	bytes, _ := makeRequest(apiURL, res, jwt)
	log.Printf("GET %s\n%s\n", res, string(bytes))
}

func makeRequest(apiURL, endpoint string, jwt OAuthResponse) ([]byte, error) {
	httpClient := http.Client{}

	uri := apiURL + endpoint
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Printf("could not create HTTP request: %v", err)
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt.AccessToken)
	req.Header.Set("user-agent", userAgent)
	res, err := httpClient.Do(req)
	if err != nil {
		log.Printf("could not send HTTP request: %v", err)
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return bytes, nil
}
