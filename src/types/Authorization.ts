import { Request } from 'express';
import { ParsedQs } from 'qs';

export interface AuthServer {
  authorizationEndpoint: string;
  tokenEndpoint: string;
}

export interface Client {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  scope: string;
}

type authorizeQueryKeys = 'client_id' | 'redirect_uri' | 'scope' | 'error';

export interface AuthorizeRequest extends Request {
  query: {
    [key in authorizeQueryKeys]: string;
  };
}

export interface AuthorizeParsedQs extends ParsedQs {
  client_id: string;
  redirect_uri: string;
  state?: string;
}

type approveBodyKeys = 'reqid' | 'approve' | 'user';

export interface ApproveRequest extends Request {
  body: {
    [key in approveBodyKeys]: string;
  };
  query: {
    [key in authorizeQueryKeys]: string;
  };
}

export interface Code {
  authorizationEndpointRequest: AuthorizeParsedQs;
  scope: string[];
  user: string;
}

type tokenBodyKeys = 'client_id' | 'client_secret' | 'grant_type' | 'code';

export interface TokenRequest extends Request {
  body: {
    [key in tokenBodyKeys]: string;
  };
}

type accessTokenBodyKeys = 'access_token';
type accessTokenQueryKeys = 'access_token';

export interface AccessTokenRequest extends Request {
  // body: {
  //   [key in accessTokenBodyKeys]: string;
  // };
  query: {
    [key in accessTokenQueryKeys]: string;
  };
  accessToken: string;
}
