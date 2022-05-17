const Config = require("../../config/config.js");
const ConfigAuth = require("../../config/authenticators.json");
const { Issuer } = require('openid-client');


class MicrosoftAuthenticator {

    constructor(state) {
        this.name = "Microsoft";
        this.client_id = ConfigAuth.microsoft.client_id;
        this.client_secret = ConfigAuth.microsoft.client_secret;
        this.response_type = "code";
        this.redirect_uri = Config.home + "/select/";
        this.scope = "openid email profile User.ReadBasic.All";
        this.resource = "https://graph.microsoft.com";
        this.prompt = "consent"; //login|consent
        this.response_mode = "form_post";
        this.state = state;
        this.nonce = state;
        this.graph_endpoint = "https://graph.microsoft.com/v1.0/me";

        let issuer = new Issuer({ 
            issuer: ConfigAuth.microsoft.issuer,
            authorization_endpoint: ConfigAuth.microsoft.authorization_endpoint,
            token_endpoint: ConfigAuth.microsoft.token_endpoint,
            userinfo_endpoint: ConfigAuth.microsoft.userinfo_endpoint,
            jwks_uri: ConfigAuth.microsoft.jwks_uri,
        });
 
        Issuer.defaultHttpOptions = { timeout: 30000 }; 

        this.client = new issuer.Client({
            client_id: this.client_id,
            client_secret: this.client_secret
        });

        this.client.CLOCK_TOLERANCE = 5; // to allow a 5 second skew
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

        ).then((tokenSet)=> {;
            this.client.userinfo(tokenSet)
            .then((userinfo)=> {
                result(this.map(userinfo));
            }).catch((e)=> {
                error(e);
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

    static getLogoutURL(redirect_uri) {
        let logoutURL = ConfigAuth.microsoft.logout_url + "?redirect_uri=" + redirect_uri;
        return logoutURL; 
    }
}


module.exports = MicrosoftAuthenticator;
