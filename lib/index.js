const fs = require('fs');
const jwkToPem = require('jwk-to-pem');
const request = require('request-promise');
const jwt = require('jsonwebtoken');

function getISS(options) {
	return `https://cognito-idp.${options.region}.amazonaws.com/${options.userPoolId}`;
}

function getPems(options) {
	return new Promise((resolve, reject) => {
		if (options.filepath) {
			// load jwks from file
			fs.readFile(options.filepath, { encoding: 'utf8' }, (err, content) => {
				if (err) {
					return reject(`Unable to read certificate due to ${err}`);
				}

				return resolve(initPems(content));
			});
		} else {
			// load jwks from download
			const cognitoPath = getISS(options);
			return request(`${cognitoPath}/.well-known/jwks.json`)
				.then(response => {
					return resolve(initPems(response));
				})
				.catch(err => {
					return reject(`Unable to generate certificate due to \n${err}`);
				});
		}
	});
}

function initPems(content) {
	const pems = {};
	let keys = JSON.parse(content)['keys'];

	keys.forEach(({kid, n, e, kty}) => {
		let jwk = { kty, n, e };
		let pem = jwkToPem(jwk);
		pems[kid] = pem;
	});

	return pems;
}

async function validate(token, options) {
	return new Promise(async (resolve, reject) => {
		try {
			const params = decodeJwt(token, options);
			const payload = await verifyJwt(params);

			return resolve(payload);
		} catch (err) {
			return reject(err);
		}
	});
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

function decodeJwt(token, options) {
	let decodedJwt = jwt.decode(token, { complete: true });

	if (!decodedJwt) {
		throw new Error('Not a valid JWT token');
	}

	const iss = getISS(options);
	console.log('ISS: ', iss);
	if (decodedJwt.payload.iss !== iss) {
		throw new Error('Token is not from your User Pool');
	}

	if (decodedJwt.payload.token_use !== options.tokenUse) {
		throw new Error(`Not an ${options.tokenUse} token`);
	}

	let kid = decodedJwt.header.kid;
	let pem = options.pems[kid];

	if (!pem) {
		throw new Error(`Invalid ${options.tokenUse} token`);
	}

	return {
		token: token,
		pem: pem,
		alg: options.alg,
		iss,
		maxAge: options.tokenExpiration
	};
}

function verifyJwt(options) {
	return new Promise((resolve, reject) => {
		jwt.verify(
			options.token,
			options.pem,
			{
				issuer: options.iss,
				maxAge: options.maxAge,
				algorithms: [options.alg]
			},
			(err, payload) => {
				if (err) {
					return reject(err);
				}

				return resolve(payload);
			}
		);
	});
}

module.exports = {
	getPems,
	validate,
	decodeJwt,
	verifyJwt
};
