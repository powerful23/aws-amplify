import { ConsoleLogger as Logger } from './Logger';
import { StorageHelper } from './StorageHelper';
import { makeQuerablePromise } from './JS';
import { FacebookOAuth, GoogleOAuth } from './OAuthHelper';
import { ICredentials } from './types';
import { Amplify } from './Amplify';
import axios from 'axios';

const logger = new Logger('Credentials');

export class CredentialsClass {
    private _config;
    private _credentials;
    private _credentials_source;
    private _gettingCredPromise = null;
    private _refreshHandlers = {};
    private _storage;
    private _storageSync;
    private _mem = {};

    constructor(config) {
        this.configure(config);
        this._refreshHandlers['google'] = GoogleOAuth.refreshGoogleToken;
        this._refreshHandlers['facebook'] = FacebookOAuth.refreshFacebookToken;
    }

    public getCredSource() {
        return this._credentials_source;
    }

    public configure(config){
        if (!config) return this._config || {};

        this._config = Object.assign({}, this._config, config);
        const { refreshHandlers } = this._config;
         // If the developer has provided an object of refresh handlers,
        // then we can merge the provided handlers with the current handlers.
        if (refreshHandlers) {
            this._refreshHandlers = { ...this._refreshHandlers,  ...refreshHandlers };
        }

        this._storage = this._config.storage;
        if (!this._storage) {
            this._storage = new StorageHelper().getStorage();
        }
        
        this._storageSync = Promise.resolve();
        if (typeof this._storage['sync'] === 'function') {
            this._storageSync = this._storage['sync']();
        }

        return this._config;
    }

    public get() {
        logger.debug('getting credentials');
        return this._pickupCredentials();
    }

    private _pickupCredentials() {
        logger.debug('picking up credentials');
        if (!this._gettingCredPromise || !this._gettingCredPromise.isPending()) {
            logger.debug('getting new cred promise');
            // if (AWS.config && AWS.config.credentials && AWS.config.credentials instanceof AWS.Credentials) {
            //     this._gettingCredPromise = makeQuerablePromise(this._setCredentialsFromAWS());
            // } else {
                this._gettingCredPromise = makeQuerablePromise(this._keepAlive());
            // }
        } else {
            logger.debug('getting old cred promise');
        }

        return this._gettingCredPromise;
    }

    private _keepAlive() {
        logger.debug('checking if credentials exists and not expired');
        const cred = this._credentials;
        if (cred && !this._isExpired(cred)) {
            logger.debug('credentials not changed and not expired, directly return');
            return Promise.resolve(cred);
        }

        logger.debug('need to get a new credential or refresh the existing one');
        if (Amplify.Auth && typeof Amplify.Auth.currentUserCredentials === 'function') {
            return Amplify.Auth.currentUserCredentials();
        } else {
            return Promise.reject('No Auth module registered in Amplify');
        }
    }

    public refreshFederatedToken(federatedInfo) {
        logger.debug('Getting federated credentials');
        const { provider, user } = federatedInfo;
        let token = federatedInfo.token;
        let expires_at = federatedInfo.expires_at;
        let identity_id = federatedInfo.identity_id;

        const that = this;
        logger.debug('checking if federated jwt token expired');
        if (expires_at > new Date().getTime()) {
            // if not expired
            logger.debug('token not expired');
            return this._setCredentialsFromFederation({provider, token, user, identity_id, expires_at });
        } else {
            // if refresh handler exists
            if (that._refreshHandlers[provider] && typeof that._refreshHandlers[provider] === 'function') {
                logger.debug('getting refreshed jwt token from federation provider');
                return that._refreshHandlers[provider]().then((data) => {
                    logger.debug('refresh federated token sucessfully', data);
                    token = data.token;
                    identity_id = data.identity_id;
                    expires_at = data.expires_at;
                    
                    return that._setCredentialsFromFederation({ provider, token, user, identity_id, expires_at });
                }).catch(e => {
                    logger.debug('refresh federated token failed', e);
                    this.clear();
                    return Promise.reject('refreshing federation token failed: ' + e);
                });
            } else {
                logger.debug('no refresh handler for provider:', provider);
                this.clear();
                return Promise.reject('no refresh handler for provider');
            }
        }
    }

    private _isExpired(credentials): boolean {
        if (!credentials) {
            logger.debug('no credentials for expiration check');
            return true;
        }
        logger.debug('is this credentials expired?', credentials);
        const ts = new Date().getTime();
        const delta = 10 * 60 * 1000; // 10 minutes
        const { expired, expireTime } = credentials;
        if (!expired && expireTime > ts + delta) {
            return false;
        }
        return true;
    }

    private async _setCredentialsForGuest() {
        let attempted = false;
        logger.debug('setting credentials for guest');
        const { identityPoolId, region, mandatorySignIn } = this._config;
        if (mandatorySignIn) {
            return Promise.reject('cannot get guest credentials when mandatory signin enabled');
        }

        if (!identityPoolId) {
            logger.debug('No Cognito Federated Identity pool provided');
            return Promise.reject('No Cognito Federated Identity pool provided');
        }

        const client = new MyCognitoIdentityCredentialsClient({
            identityPoolId,
            region
        });

        const that = this;
        return this._loadCredentials(client, 'guest', false, null)
        .then((res) => {
            return res;
         })
        .catch(async (e) => {
            // If identity id is deleted in the console, we make one attempt to recreate it
            // and remove existing id from cache. 
            if (e.code === 'ResourceNotFoundException' &&
                e.message === `Identity '${client.identityId}' not found.`
                && !attempted) {
                attempted = true;
                logger.debug('Failed to load guest credentials');
                await this._removeCachedId(false);
                const newCredentials = new MyCognitoIdentityCredentialsClient({
                    identityPoolId,
                    region
                });
                return this._loadCredentials(newCredentials, 'guest', false, null);
            } else {
                throw e;
            }
        });
    }

    // private _setCredentialsFromAWS() {
    //     const credentials = AWS.config.credentials;
    //     logger.debug('setting credentials from aws');
    //     const that = this;
    //     if (credentials instanceof AWS.Credentials){
    //         return Promise.resolve(credentials);
    //     } else {
    //         logger.debug('AWS.config.credentials is not an instance of AWS Credentials');
    //         return Promise.reject('AWS.config.credentials is not an instance of AWS Credentials');
    //     }
    // }

    private _setCredentialsFromFederation(params) {
        const { provider, token, identity_id, user, expires_at } = params;
        const domains = {
            'google': 'accounts.google.com',
            'facebook': 'graph.facebook.com',
            'amazon': 'www.amazon.com',
            'developer': 'cognito-identity.amazonaws.com'
        };

        // Use custom provider url instead of the predefined ones
        const domain = domains[provider] || provider;
        if (!domain) {
            return Promise.reject('You must specify a federated provider');
        }

        const logins = {};
        logins[domain] = token;

        const { identityPoolId, region } = this._config;
        if (!identityPoolId) {
            logger.debug('No Cognito Federated Identity pool provided');
            return Promise.reject('No Cognito Federated Identity pool provided');
        }

        const client = new MyCognitoIdentityCredentialsClient({
            identityPoolId,
            identityId: identity_id,
            logins,
            region
        });

        return this._loadCredentials(
            client, 
            'federated', 
            true, 
            params,
        );
    }

    private _setCredentialsFromSession(session): Promise<ICredentials> {
        logger.debug('set credentials from session');
        const idToken = session.getIdToken().getJwtToken();
        const { region, userPoolId, identityPoolId } = this._config;
        if (!identityPoolId) {
            logger.debug('No Cognito Federated Identity pool provided');
            return Promise.reject('No Cognito Federated Identity pool provided');
        }
        const key = 'cognito-idp.' + region + '.amazonaws.com/' + userPoolId;
        const logins = {};
        logins[key] = idToken;
        const client = new MyCognitoIdentityCredentialsClient({
            identityPoolId,
            logins,
            region
        });

        const that = this;
        return this._loadCredentials(client, 'userPool', true, null);
    }

    private async _getCachedId(authenticated) {
        const { identityPoolId } = this._config;
        if (authenticated) {
            return this._mem[`CognitoIdentityId-${identityPoolId}-authenticated`];
        } else {
            await this._storageSync;
            return this._storage.getItem(`CognitoIdentityId-${identityPoolId}`);
        }
    }

    private async _setCachedId(authenticated, identityId) {
        const { identityPoolId } = this._config;
        if (authenticated) {
            this._mem[`CognitoIdentityId-${identityPoolId}-authenticated`] = identityId;
        } else {
            await this._storage.setItem(`CognitoIdentityId-${identityPoolId}`, identityId);
        }
    }

    private async _removeCachedId(authenticated) {
        const { identityPoolId } = this._config;
        if (authenticated) {
            delete this._mem[`CognitoIdentityId-${identityPoolId}-authenticated`];
        } else {
            await this._storage.removeItem(`CognitoIdentityId-${identityPoolId}`);
        }
    }

    private async _loadCredentials(client, source, authenticated, info): Promise<ICredentials> {
        const { identityPoolId } = this._config;

        try {
            if (!client.identityId) {
                let identityId = await this._getCachedId(authenticated);
                if (!identityId) {
                    identityId = (await client.getIdentityId()).IdentityId;
                    this._setCachedId(authenticated, identityId);
                }
                client.identityId = identityId;
            }
            this._credentials = await client.getCredentials();
            this._credentials.authenticated = authenticated;
            this._credentials_source = source;

            if (source === 'federated') {
                const user = Object.assign(
                    { id: this._credentials.identityId },
                    info.user
                );
                const { provider, token, expires_at } = info;
                try {
                    this._storage.setItem(
                        'aws-amplify-federatedInfo',
                        JSON.stringify({
                            provider, 
                            token, 
                            user, 
                            expires_at, 
                            identity_id: this._credentials.identityId
                        })
                    );
                } catch(e) {
                    logger.debug('Failed to put federated info into auth storage', e);
                }
                // the Cache module no longer stores federated info
                // this is just for backward compatibility
                if (Amplify.Cache && typeof Amplify.Cache.setItem === 'function'){
                    Amplify.Cache.setItem(
                        'federatedInfo', 
                        { 
                            provider, 
                            token, 
                            user, 
                            expires_at, 
                            identity_id: this._credentials.identityId
                        }, 
                        { priority: 1 }
                    );
                } else {
                    logger.debug('No Cache module registered in Amplify');
                }
            }
            logger.debug('Load credentials successfully', this._credentials);
            return this._credentials;
        } catch (e) {
            logger.debug('Failed to load credentials');
            throw e;
        }
    }

    public set(params, source): Promise<ICredentials> {
        if (source === 'session') {
            return this._setCredentialsFromSession(params);
        } else if (source === 'federation') {
            return this._setCredentialsFromFederation(params);
        } else if (source === 'guest') {
            return this._setCredentialsForGuest();
        } else {
            logger.debug('no source specified for setting credentials');
            return Promise.reject('invalid source');
        }
    }

    public async clear() {
        // keep the identity id for guest users
        if (this._credentials.authenticated) this._removeCachedId(this._credentials.authenticated);
        this._credentials = null;
        this._credentials_source = null;
        this._storage.removeItem('aws-amplify-federatedInfo');

        // the Cache module no longer stores federated info
        // this is just for backward compatibility
        if (Amplify.Cache && typeof Amplify.Cache.setItem === 'function'){
            await Amplify.Cache.removeItem('federatedInfo');
        } else {
            logger.debug('No Cache module registered in Amplify');
        }
    }

    /**
     * Compact version of credentials
     * @param {Object} credentials
     * @return {Object} - Credentials
     */
    public shear(credentials) {
        return {
            accessKeyId: credentials.accessKeyId,
            sessionToken: credentials.sessionToken,
            secretAccessKey: credentials.secretAccessKey,
            identityId: credentials.identityId,
            authenticated: credentials.authenticated
        };
    }
}

class MyCognitoIdentityCredentialsClient {
    public identityPooId;
    public identityId;
    public logins;
    public region;

    constructor(params) {
        this.identityPooId = params.identityPoolId;
        this.identityId = params.identityId;
        this.logins = params.logins;
        this.region = params.region;
    }

    getCredentials() {
        return this._makeAWSRequest({
            url: `https://cognito-identity.${this.region}.amazonaws.com/`,
            target: 'AWSCognitoIdentityService.GetCredentialsForIdentity',
            data: {
                IdentityId: this.identityId,
                Logins: this.logins
            }
        }).then(data => {
            return this._generateCredentialsObj(data);
        });
    }

    getIdentityId() {
        return this._makeAWSRequest({
            url: `https://cognito-identity.${this.region}.amazonaws.com/`,
            target: 'AWSCognitoIdentityService.GetId',
            data: {
                IdentityPoolId: this.identityPooId,
                Logins: this.logins
            }
        });
    }

    _makeAWSRequest(params) {
        const { target, url, data } = params;

        const httpRequest = {
            method: 'POST',
            url,
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': target,
                'X-Amz-User-Agent': 'aws-amplify-v2.0'
            },
            data,
            responseType: 'json'
        }

        return axios(httpRequest).then(resp => {
            return this._extractData(resp);
        }).catch(e => {
            throw this._extractError(e);
        });
    }

    _extractData(respObj) {
        return respObj.data;
    }

    _generateCredentialsObj(data) {
        // for backward compatibility
        const credentials:any = {};
        credentials.expired = false;
        credentials.accessKeyId = data.Credentials.AccessKeyId;
        credentials.sessionToken = data.Credentials.SessionToken;
        credentials.secretAccessKey = data.Credentials.SecretKey;
        credentials.expireTime = data.Credentials.Expiration;
        credentials.identityId = data.IdentityId;
        credentials.data = data;
        return credentials;
    }

    _extractError(errorObj) {
        const error:any = {};
        var httpResponse = errorObj.response;

        error.code = httpResponse.headers['x-amzn-errortype'] || 'UnknownError';
        if (typeof error.code === 'string') {
            error.code = error.code.split(':')[0];
        }

        if (httpResponse.data) {
            const e = httpResponse.data;
            if (e.__type || e.code) {
                error.code = (e.__type || e.code).split('#').pop();
            }
            if (error.code === 'RequestEntityTooLarge') {
                error.message = 'Request body must be less than 1 MB';
            } else {
                error.message = (e.message || e.Message || null);
            }  
        } else {
            error.statusCode = httpResponse.status;
            error.message = httpResponse.status.toString();
        }

        return generateError(new Error(), error);
    }
}

function generateError(err, options) {
    var originalError = null;
    if (typeof err.message === 'string' && err.message !== '') {
      if (typeof options === 'string' || (options && options.message)) {
        originalError = copy(err);
        originalError.message = err.message;
      }
    }
    err.message = err.message || null;

    if (typeof options === 'string') {
      err.message = options;
    } else if (typeof options === 'object' && options !== null) {
      update(err, options);
      if (options.message)
        err.message = options.message;
      if (options.code || options.name)
        err.code = options.code || options.name;
      if (options.stack)
        err.stack = options.stack;
    }

    if (typeof Object.defineProperty === 'function') {
      Object.defineProperty(err, 'name', {writable: true, enumerable: false});
      Object.defineProperty(err, 'message', {enumerable: true});
    }

    err.name = options && options.name || err.name || err.code || 'Error';
    err.time = new Date();

    if (originalError) err.originalError = originalError;

    return err;
}

function copy(object) {
    if (object === null || object === undefined) return object;
    var dupe = {};
    // jshint forin:false
    for (var key in object) {
      dupe[key] = object[key];
    }
    return dupe;
}

function update(obj1, obj2) {
    each(obj2, function iterator(key, item) {
        obj1[key] = item;
    });
    return obj1;
}

function each(object, iterFunction) {
    for (var key in object) {
        if (Object.prototype.hasOwnProperty.call(object, key)) {
            var ret = iterFunction.call(this, key, object[key]);
            if (ret === {}) break;
        }
    }
}


export const Credentials = new CredentialsClass(null);

/**
 * @deprecated use named import
 */
export default Credentials;
