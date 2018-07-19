'use strict';

const jwkToPem = require('jwk-to-pem');
const request = require('request-promise');
const jwt = require('jsonwebtoken');

class CognitoExpress {
	constructor(config) {
		if (!config) {
			throw new TypeError(
				'Options not found. Please refer to README for usage example at https://github.com/ghdna/cognito-express'
			);
		}

		if (isConfigurationCorrect(config)) {
			this.userPoolId = config.cognitoUserPoolId;
			this.tokenUse = config.tokenUse;
			this.alg = config.alg || 'RS256';
			this.tokenExpiration = config.tokenExpiration || 3600000;
			this.filepath = config.filepath || null;
			this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${this.userPoolId}`;
			this.promise = this.init(callback => {});
			this.pems = {};
		}
	}

	init(callback) {
		if (this.filePath) {
			// load jwks from file
			fs.readFile(this.filepath, { encoding: 'utf8' }, (err, content) => {
				if (err) {
					throw new TypeError('Unable to generate certificate due to \n' + err);
					return callback(false);
				}
				this.initPems(content);

				return callback(true);
			});
		} else {
			// load jwks from download
			return request(`${this.iss}/.well-known/jwks.json`)
				.then(response => {
					this.initPems(response);

					return callback(true);
				})
				.catch(err => {
					throw new TypeError('Unable to generate certificate due to \n' + err);
					return callback(false);
				});
		}
	}

	initPems(content) {
		this.pems = {};
		let keys = JSON.parse(content)['keys'];

		keys.forEach(({kid, n, e, kty}) => {
			let jwk = { kty, n, e };
			let pem = jwkToPem(jwk);
			this.pems[kid] = pem;
		});
	}

	async validate(token, callback) {
		return new Promise(async (resolve, reject) => {
			let decodedJwt = jwt.decode(token, { complete: true });

			if (!decodedJwt) {
				return reject('Not a valid JWT token');
			}

			if (decodedJwt.payload.iss !== this.iss) {
				return reject('Token is not from your User Pool');
			}

			if (decodedJwt.payload.token_use !== this.tokenUse) {
				return reject(`Not an ${this.tokenUse} token`);
			}

			let kid = decodedJwt.header.kid;
			let pem = this.pems[kid];

			if (!pem) {
				return reject(`Invalid ${this.tokenUse} token`);
			}

			let params = {
				token: token,
				pem: pem,
				alg: this.alg,
				iss: this.iss,
				maxAge: this.tokenExpiration
			};

			return verifyJwt(params, (err, payload) => {
				if (err) {
					return reject(err);
				}

				return resolve(payload);
			});
		});
	}
}

function isConfigurationCorrect(config) {
	let configurationPassed = false;
	switch (true) {
		case !config.region:
			throw new TypeError('AWS Region not specified in constructor');
			break;

		case !config.cognitoUserPoolId:
			throw new TypeError('Cognito User Pool ID is not specified in constructor');
			break;

		case !config.tokenUse:
			throw new TypeError(`Token use not specified in constructor. Possible values 'access' | 'id'`);
			break;

		case !(config.tokenUse == 'access' || config.tokenUse == 'id'):
			throw new TypeError(`Token use values not accurate in the constructor. Possible values 'access' | 'id'`);
			break;

		default:
			configurationPassed = true;
	}
	return configurationPassed;
}

function verifyJwt(params, callback) {
	jwt.verify(
		params.token,
		params.pem,
		{
			issuer: params.iss,
			maxAge: params.maxAge,
			algorithms: [params.alg]
		},
		function(err, payload) {
			if (err) return callback(err);

			return callback(null, payload);
		}
	);
}

module.exports = CognitoExpress;
