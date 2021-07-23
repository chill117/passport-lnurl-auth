const _ = require('underscore');
const crypto = require('crypto');
const http = require('http');
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
		return match && match[1] || null;
	},

	extractEncodedFromLoginPageHtml: function(html) {
		const match = html.match(new RegExp('<a id="qrcode" href="(lightning:|LIGHTNING:)?([a-zA-Z0-9]+)">'));
		return match && match[2] || null;
	},

	extractSecretFromLoginPageHtml: function(html) {
		let secret;
		const encoded = this.extractEncodedFromLoginPageHtml(html);
		if (encoded) {
			const decoded = lnurl.decode(encoded);
			const parsedUrl = url.parse(decoded);
			const params = querystring.parse(parsedUrl.query);
			secret = params.k1;
		}
		return secret;
	},

	request: function(method, requestOptions, cb) {
		const done = _.once(cb);
		const parsedUrl = url.parse(requestOptions.url);
		let options = _.extend({}, requestOptions || {}, {
			method: method.toUpperCase(),
			hostname: parsedUrl.hostname,
			port: parsedUrl.port,
			path: parsedUrl.path,
		});
		if (requestOptions.qs) {
			options.path += '?' + querystring.stringify(requestOptions.qs);
		}
		const req = http.request(options, function(res) {
			let body = '';
			res.on('data', function(buffer) {
				body += buffer.toString();
			});
			res.on('end', function() {
				if (requestOptions.json) {
					try {
						body = JSON.parse(body);
					} catch (error) {
						return done(error);
					}
				}
				done(null, res, body);
			});
		});
		req.once('error', done);
		req.end();
	},
};
