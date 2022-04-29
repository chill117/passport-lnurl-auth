const assert = require('assert');
const http = require('http');
const https = require('https');
const lnurl = require('lnurl');
const { createAuthorizationSignature, generateRandomLinkingKey } = require('lnurl/lib');
const querystring = require('querystring');
const url = require('url');

module.exports = {

	doSigning: function(k1, linkingKey) {
		linkingKey = linkingKey || generateRandomLinkingKey();
		const { pubKey, privKey } = linkingKey;
		const sig = createAuthorizationSignature(k1, privKey);
		return {
			sig: sig.toString('hex'),
			key: pubKey.toString('hex'),
		};
	},

	extractDataUriFromLoginPageHtml: function(html) {
		const match = html.match(new RegExp('<img src="data:image/png;base64,([^",]+)">'));
		const dataUri = match && match[1] || null;
		assert.ok(dataUri, 'Data URI not found in HTML:\n' + html);
		return dataUri;
	},

	extractEncodedFromLoginPageHtml: function(html) {
		const match = html.match(new RegExp('<a id="qrcode" href="(lightning:|LIGHTNING:)?([a-zA-Z0-9]+)">'));
		const encoded = match && match[2] || null;
		assert.ok(encoded, 'Encoded LNURL not found in HTML:\n' + html);
		return encoded;
	},

	extractSecretFromLoginPageHtml: function(html) {
		let secret;
		const encoded = this.extractEncodedFromLoginPageHtml(html);
		if (encoded) {
			const decoded = lnurl.decode(encoded);
			const { query } = url.parse(decoded, true);
			secret = query.k1;
		}
		assert.ok(secret, 'Secret not found in HTML:\n' + html);
		return secret;
	},
	request: function(method, requestOptions) {
		return new Promise((resolve, reject) => {
			try {
				const parsedUrl = url.parse(requestOptions.url);
				let options = {
					method: method.toUpperCase(),
					hostname: parsedUrl.hostname,
					port: parsedUrl.port,
					path: parsedUrl.path,
					headers: requestOptions.headers || {},
				};
				if (requestOptions.qs) {
					options.path += '?' + querystring.stringify(requestOptions.qs);
				}
				let postData;
				if (requestOptions.form) {
					options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
					postData = querystring.stringify(requestOptions.form);
				} else if (requestOptions.body && requestOptions.json) {
					options.headers['Content-Type'] = 'application/json';
					postData = querystring.stringify(requestOptions.body);
				}
				if (postData) {
					options.headers['Content-Length'] = Buffer.byteLength(postData);
				}
				const request = parsedUrl.protocol === 'https:' ? https.request : http.request;
				const req = request(options, function(response) {
					let body = '';
					response.on('data', function(buffer) {
						body += buffer.toString();
					});
					response.on('end', function() {
						if (response.headers['content-type'].substr(0, 'application/json'.length) === 'application/json') {
							try { body = JSON.parse(body); } catch (error) {
								return reject(error);
							}
						}
						resolve({ response, body });
					});
				});
				if (postData) {
					req.write(postData);
				}
				req.once('error', reject);
				req.end();
			} catch (error) {
				return reject(error);
			}
		});
	},
};
