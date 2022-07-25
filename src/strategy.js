/**
 * Passport Strategy that implements "Sign in with Apple"
 * @author: Ananay Arora <i@ananayarora.com>
 */

 const OAuth2Strategy = require('passport-oauth2'),
 crypto = require('crypto'),
 AppleClientSecret = require("./token"),
 util = require('util'),
 utils = require('./utils'),
 url = require('url'),
 jwt_decode = require('jwt-decode'),
 querystring = require('querystring');

/**
* Passport Strategy Constructor
*
* Example:
*
*   passport.use(new AppleStrategy({
*      clientID: "",
*      teamID: "",
*      callbackURL: "",
*      keyID: "",
*      privateKeyLocation: "",
*      passReqToCallback: true
*   }, function(req, accessToken, refreshToken, idToken, __ , cb) {
*       // The idToken returned is encoded. You can use the jsonwebtoken library via jwt.decode(idToken)
*       // to access the properties of the decoded idToken properties which contains the user's
*       // identity information.
*       // Here, check if the idToken.sub exists in your database!
*       // __ parameter is REQUIRED for the sake of passport implementation
*       // it should be profile in the future but apple hasn't implemented passing data
*       // in access token yet https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
*       cb(null, idToken);
*   }));
*
* @param {object} options - Configuration options
* @param {string} options.clientID – Client ID (also known as the Services ID
*  in Apple's Developer Portal). Example: com.ananayarora.app
* @param {string} options.teamID – Team ID for the Apple Developer Account
*  found on top right corner of the developers page
* @param {string} options.keyID – The identifier for the private key on the Apple
*  Developer Account page
* @param {string} options.callbackURL – The OAuth Redirect URI
* @param {string} options.privateKeyLocation - Location to the private key
* @param {string} options.privateKeyString - Private key string
* @param {boolean} options.passReqToCallback - Determine if the req will be passed to passport cb function
* @param {function} verify
* @access public
*/
function Strategy(options, verify) {
 // Set the URLs
 options = options || {};
 options.authorizationURL = options.authorizationURL || 'https://appleid.apple.com/auth/authorize';
 options.tokenURL = options.tokenURL || 'https://appleid.apple.com/auth/token';
 options.passReqToCallback = options.passReqToCallback === undefined ? true : options.passReqToCallback
 debugger;
 // Make the OAuth call
 OAuth2Strategy.call(this, options, verify);
 this.name = 'apple';

 // Initiliaze the client_secret generator
 const _tokenGenerator = new AppleClientSecret({
     "client_id": options.clientID,
     "team_id": options.teamID,
     "key_id": options.keyID
 }, options.privateKeyLocation, options.privateKeyString);

 // Get the OAuth Access Token from Apple's server
 // using the grant code / refresh token.

 this._oauth2.getOAuthAccessToken = function(code, params, callback) {
     // Generate the client_secret using the library
     _tokenGenerator.generate().then((client_secret) => {
         params = params || {};
         const codeParam = params.grant_type === 'refresh_token' ? 'refresh_token' : 'code';
         params[codeParam] = code;
         params['client_id'] = this._clientId;
         params['client_secret'] = client_secret;

         const post_data = querystring.stringify(params);
         const post_headers = {
             'Content-Type': 'application/x-www-form-urlencoded'
         };
         this._request(
             'POST',
             this._getAccessTokenUrl(),
             post_headers,
             post_data,
             null,
             function(error, data, response) {
                 if (error) {
                     callback(error);
                 } else {
                     const results = JSON.parse(data);
                     const access_token = results.access_token;
                     const refresh_token = results.refresh_token;
                     callback(null, access_token, refresh_token, results.id_token);
                 }
             }
         )
     }).catch((error) => {
         callback(error);
     });
 }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);

/**
* Process the authentication request
* @param {http.IncomingMessage} req
* @param {object} options
* @access protected
*/
Strategy.prototype.authenticate = function (req, options) {
 // Workaround instead of reimplementing authenticate function
 debugger;
 req.query = { ...req.query, ...req.body };
 if(req.body && req.body.user){
     req.appleProfile = JSON.parse(req.body.user)
 } 
 if (req.body && req.body.id_token) {
     req.id_token = jwt_decode(req.body.id_token);
 }
 //OAuth2Strategy.prototype.authenticate.call(this, req, options);
 debugger;
 options = options || {};
 var self = this;

 if (req.query && req.query.error) {
   if (req.query.error == 'access_denied') {
     return this.fail({ message: req.query.error_description });
   } else {
     return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
   }
 }

 var callbackURL = options.callbackURL || this._callbackURL;
 if (callbackURL) {
   var parsed = url.parse(callbackURL);
   if (!parsed.protocol) {
     // The callback URL is relative, resolve a fully qualified URL from the
     // URL of the originating request.
     callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
   }
 }

 var meta = {
   authorizationURL: this._oauth2._authorizeUrl,
   tokenURL: this._oauth2._accessTokenUrl,
   clientID: this._oauth2._clientId,
   callbackURL: callbackURL
 }

 if (req.query && req.query.code) {
   function loaded(err, ok, state) {
     if (err) { return self.error(err); }
     if (!ok) {
       return self.fail(state, 403);
     }

     var code = req.query.code;

     var params = self.tokenParams(options);
     params.grant_type = 'authorization_code';
     if (callbackURL) { params.redirect_uri = callbackURL; }
     if (typeof ok == 'string') { // PKCE
       params.code_verifier = ok;
     }

     self._oauth2.getOAuthAccessToken(code, params,
       function(err, accessToken, refreshToken, params) {
         if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
         if (!accessToken) { return self.error(new Error('Failed to obtain access token')); }

         self._loadUserProfile(accessToken, function(err, profile) {
             if (err) { return self.error(err); }

             function verified(err, user, info) {
                 if (err) { return self.error(err); }
                 if (!user) { return self.fail(info); }

                 info = info || {};
                 if (state) { info.state = state; }
                 self.success(user, info);
             }

             profile = {};
             if (req.appleProfile) { 
                 profile.id = req.id_token.sub;
                 profile.email = req.appleProfile.email;
             } else {
                 profile.id = req.id_token.sub;
                 profile.email = req.id_token.email;
             }

             try {
                 if (self._passReqToCallback) {
                   var arity = self._verify.length;
                   if (arity == 6) {
                     self._verify(req, accessToken, refreshToken, params, profile, verified);
                   } else { // arity == 5
                     self._verify(req, accessToken, refreshToken, profile, verified);
                   }
                 } else {
                   var arity = self._verify.length;
                   if (arity == 5) {
                     self._verify(accessToken, refreshToken, params, profile, verified);
                   } else { // arity == 4
                     self._verify(accessToken, refreshToken, profile, verified);
                   }
                 }
             } catch (ex) {
                 return self.error(ex);
             }
         });
       }
     );
   }

   var state = req.query.state;
   try {
     var arity = this._stateStore.verify.length;
     if (arity == 4) {
       this._stateStore.verify(req, state, meta, loaded);
     } else { // arity == 3
       this._stateStore.verify(req, state, loaded);
     }
   } catch (ex) {
     return this.error(ex);
   }
 } else {
   debugger;
   var params = this.authorizationParams(options);
   params.response_type = options.response_type || 'code';
   if (callbackURL) { params.redirect_uri = callbackURL; }
   var scope = options.scope || this._scope;
   if (scope) {
     if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
     params.scope = scope;
   }
   var verifier, challenge;

   if (this._pkceMethod) {
     verifier = base64url(crypto.pseudoRandomBytes(32))
     switch (this._pkceMethod) {
     case 'plain':
       challenge = verifier;
       break;
     case 'S256':
       challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
       break;
     default:
       return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
     }

     params.code_challenge = challenge;
     params.code_challenge_method = this._pkceMethod;
   }

   var state = options.state;
   if (state && typeof state == 'string') {
     // NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
     //       an object.  However, it would result in an empty string being
     //       serialized as the value of the query parameter by `url.format()`,
     //       effectively ignoring the option.  This implies that `state` was
     //       only functional when passed as a string value.
     //
     //       This fact is taken advantage of here to fall into the `else`
     //       branch below when `state` is passed as an object.  In that case
     //       the state will be automatically managed and persisted by the
     //       state store.
     params.state = state;
     
     var parsed = url.parse(this._oauth2._authorizeUrl, true);
     utils.merge(parsed.query, params);
     parsed.query['client_id'] = this._oauth2._clientId;
     delete parsed.search;
     var location = url.format(parsed);
     this.redirect(location);
   } else {
     function stored(err, state) {
       if (err) { return self.error(err); }

       if (state) { params.state = state; }
       var parsed = url.parse(self._oauth2._authorizeUrl, true);
       utils.merge(parsed.query, params);
       parsed.query['client_id'] = self._oauth2._clientId;
       delete parsed.search;
       var location = url.format(parsed);
       self.redirect(location);
     }

     try {
       var arity = this._stateStore.store.length;
       if (arity == 5) {
         this._stateStore.store(req, verifier, state, meta, stored);
       } else if (arity == 4) {
         this._stateStore.store(req, state, meta, stored);
       } else if (arity == 3) {
         this._stateStore.store(req, meta, stored);
       } else { // arity == 2
         this._stateStore.store(req, stored);
       }
     } catch (ex) {
       return this.error(ex);
     }
   }
 }
};

/**
* Modify the authorization params. Currently adds
* the missing `state` parameter
* @param {object} options
* @access protected
*/
Strategy.prototype.authorizationParams = function (options) {
 debugger;
 //options.state = options.state || crypto.randomBytes(5).toString('hex');
 options.response_type = "code id_token";
 return options;
}

// Expose Strategy.
exports = module.exports = Strategy;

// Exports.
exports.Strategy = Strategy;
