package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/joho/godotenv/autoload"
	"github.com/mrjones/oauth"
)

var token = ""

var notAuthenticatedTemplate = template.Must(template.New("").Parse(`
<html><body>
Auth w/ Twitter:
<form action="/authorize" method="POST"><input type="submit" value="Ok, authorize this app with my id"/></form>
</body></html>
`))

var userInfoTemplate = template.Must(template.New("").Parse(`
<html><body>
Got Milk.
</body></html>
`))

var c = oauth.NewConsumer(
	os.Getenv("TWITTER_KEY"),
	os.Getenv("TWITTER_SECRET"),
	oauth.ServiceProvider{
		RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
		AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
		AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
	},
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

func init() {
	gob.Register(&oauth.RequestToken{})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", HomePageHandler)
	r.HandleFunc("/authorize", AuthorizeHandler)
	r.HandleFunc("/oauth_callback", OauthCallbackHandler)
	server := &http.Server{Handler: r}
	listener, err := net.Listen("tcp", ":5000")
	if nil != err {
		log.Fatalln(err)
	}
	if err := server.Serve(listener); nil != err {
		log.Fatalln(err)
	}
}

func HomePageHandler(w http.ResponseWriter, r *http.Request) {
	notAuthenticatedTemplate.Execute(w, nil)
}

func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	tokenUrl := fmt.Sprintf("http://%s/oauth_callback", r.Host)
	token, requestUrl, err := c.GetRequestTokenAndUrl(tokenUrl)
	if err != nil {
		log.Fatal(err)
	}
	session, _ := store.Get(r, "sign-in-with-twitter")
	session.Values[token.Token] = token
	sessionErr := session.Save(r, w)
	if sessionErr != nil {
		log.Fatal(sessionErr)
	}
	http.Redirect(w, r, requestUrl, http.StatusFound)
}

func OauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "sign-in-with-twitter")
	values := r.URL.Query()
	verificationCode := values.Get("oauth_verifier")
	tokenKey := values.Get("oauth_token")
	token := session.Values[tokenKey]
	accessToken, err := c.AuthorizeToken(
		token.(*oauth.RequestToken),
		verificationCode,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v", accessToken)
	userInfoTemplate.Execute(w, nil)
}
