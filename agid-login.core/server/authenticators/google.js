const Config = require("../../config/config.js");
const ConfigAuth = require("../../config/authenticators.json");
const { Issuer } = require('openid-client');


class GoogleAuthenticator {

    constructor(state) {
        this.name = "Google";
        this.client_id = ConfigAuth.google.client_id;
        this.client_secret = ConfigAuth.google.client_secret;
        this.response_type = "code";
        this.redirect_uri = Config.home + "/select/";
        this.scope = "openid email profile";
        this.prompt = "login"; //login|consent
        this.response_mode = "form_post";
        this.state = state;
        this.nonce = state;

        let issuer = new Issuer({ 
            issuer: ConfigAuth.google.issuer,
            authorization_endpoint: ConfigAuth.google.authorization_endpoint,
            token_endpoint: ConfigAuth.google.token_endpoint,
            userinfo_endpoint: ConfigAuth.google.userinfo_endpoint,
            jwks_uri: ConfigAuth.google.jwks_uri,
        });

        this.client = new issuer.Client({
            client_id: this.client_id,
            client_secret: this.client_secret
        });
    }

    getAuthURL() {

        let authURL = this.client.authorizationUrl({
            response_type: this.response_type,
            redirect_uri: this.redirect_uri,
            scope: this.scope,
            prompt: this.prompt,
            response_mode: this.response_mode,
            state: this.state,
            nonce: this.nonce
        });

        return authURL;
    }

    getUserInfo(authorizationPostData, nonce, result, error) {
        this.client.authorizationCallback(
            this.redirect_uri, 
            authorizationPostData,
            { 
                state: this.state, 
                response_type: this.response_type,
                nonce: nonce
            }

        ).then((tokenSet)=> {

            this.client.userinfo(tokenSet)
            .then((userinfo)=> {
                result(this.map(userinfo));
            });
            
        }).catch((e)=> {
            error(e);
        });
    }

    map(data) {
        return {
            provider: this.name,
            provider_id: data.email,
            firstname: data.given_name,
            lastname: data.family_name,
            email: data.email
        }
    }
}


module.exports = GoogleAuthenticator;
