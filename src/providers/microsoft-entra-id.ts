import { CodeChallengeMethod, OAuth2Client } from "../client.js";
import { createOAuth2Request, sendTokenRequest } from "../request.js";

import type { OAuth2Tokens } from "../oauth2.js";

export class MicrosoftEntraId {
	private clientId: string;
	private clientSecret: string;
	private authorizationEndpoint: string;
	private tokenEndpoint: string;
	private redirectURI: string | null;

	private client: OAuth2Client;

	constructor(tenant: string, clientId: string, clientSecret: string, redirectURI: string) {
		this.authorizationEndpoint = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
		this.tokenEndpoint = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.redirectURI = redirectURI;
		this.client = new OAuth2Client(clientId, clientSecret, redirectURI);
	}

	public createAuthorizationURL(state: string, codeVerifier: string, scopes: string[]): URL {
		const url = this.client.createAuthorizationURLWithPKCE(
			this.authorizationEndpoint,
			state,
			CodeChallengeMethod.S256,
			codeVerifier,
			scopes
		);
		return url;
	}

	public async validateAuthorizationCode(
		code: string,
		codeVerifier: string
	): Promise<OAuth2Tokens> {
		const body = new URLSearchParams();
		body.set("grant_type", "authorization_code");
		body.set("code", code);
		body.set("client_id", this.clientId);
		body.set("client_secret", this.clientSecret);
		if (this.redirectURI !== null) {
			body.set("redirect_uri", this.redirectURI);
		}
		if (codeVerifier !== null) {
			body.set("code_verifier", codeVerifier);
		}
		const request = createOAuth2Request(this.tokenEndpoint, body);
		const tokens = await sendTokenRequest(request);
		return tokens;
	}

	// v3 TODO: Add `scopes` parameter
	public async refreshAccessToken(refreshToken: string): Promise<OAuth2Tokens> {
		const tokens = await this.client.refreshAccessToken(this.tokenEndpoint, refreshToken, []);
		return tokens;
	}
}
