import axios from 'axios';
import { Signer } from './Signer';

type HttpRequest = {
    method?,
    url?,
    host?,
    path?,
    headers?,
    data?,
    responseType?
}

function httpCall(params) {
    return axios(params);
}

function getParams(method, url, host, path, headers, data, responseType) {

}

function signAWSRequests(params, credentials, signerServiceInfoParams) {
    return Signer.sign(params, credentials, signerServiceInfoParams);
}

class MyCognitoCredentials {
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

    getCredentialsForIdentity() {
        const params:HttpRequest = {
            method: 'POST',
            url: `https://cognito-identity.${this.region}.amazonaws.com/`,
            host: `https://cognito-identity.${this.region}.amazonaws.com/`,
            headers: {
                'Content-Type': ' application/x-amz-json-1.1',
                'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
                'X-Amz-User-Agent': 'aws-amplify-v2.0'
            },
            data: {
                IdentityId: this.identityId,
            },
            responseType: 'json'
        }
    }
}
export { httpCall };