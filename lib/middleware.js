const assert = require('assert');
const crypto = require('crypto');
const debug = {
	error: require('debug')('passport-lnurl-auth:middleware:error'),
};
const fs = require('fs');
const lnurl = require('lnurl');
const path = require('path');
const QRCode = require('qrcode');
const querystring = require('querystring');
const { HttpError, verifyAuthorizationSignature } = require('lnurl/lib');

// Create an isolated handlebars environment:
const handlebars = require('handlebars').create();

const map = {
	session: new Map(),
};

const Middleware = function(options) {
	options = Object.assign({}, {
		// The externally reachable URL for the lnurl-auth middleware.
		// It should resolve to THIS endpoint on your server.
		callbackUrl: null,
		// The URL of the "Cancel" button on the login page.
		// When set to NULL or some other falsey value, the cancel button will be hidden.
		cancelUrl: null,
		// Instruction text shown below the title on the login page:
		instruction: 'Scan the QR code to login',
		// The file path to the login.html template:
		loginTemplateFilePath: path.join(__dirname, '..', 'templates', 'login.html'),
		// The number of seconds to wait before refreshing the login page:
		refreshSeconds: 5,
		// The title of the login page:
		title: 'Login with lnurl-auth',
		// The URI schema prefix used before the encoded LNURL.
		// e.g. "lightning:" or "LIGHTNING:" or "" (empty-string)
		uriSchemaPrefix: 'LIGHTNING:',
	}, options || {});
	options.qrcode = Object.assign({}, {
		errorCorrectionLevel: 'L',
		margin: 2,
		type: 'image/png',
	}, options.qrcode || {});
	assert.ok(options.callbackUrl, 'Missing required middleware option: "callbackUrl"');
	assert.ok(options.loginTemplateFilePath, 'Missing required middleware option: "loginTemplateFilePath"');
	options.loginTemplateFilePath = path.resolve(options.loginTemplateFilePath);
	try { fs.readFileSync(options.loginTemplateFilePath); } catch (error) {
		if (/permission denied, open/i.test(error.message)) {
			throw new Error('Invalid middleware option ("loginTemplateFilePath"): Cannot open login.html template file: Permission denied');
		} else if (/no such file or directory/i.test(error.message)) {
			throw new Error('Invalid middleware option ("loginTemplateFilePath"): Cannot open login.html template file: Does not exist');
		} else {
			throw erorr;
		}
	}
	return (req, res) => {
		return Promise.resolve().then(() => {
			if (req.query.k1 || req.query.key || req.query.sig) {
				// Check signature against provided linking public key.
				// This request could originate from a mobile app (ie. not their browser).
				let session;
				assert.ok(req.query.k1, new HttpError('Missing required parameter: "k1"', 400));
				assert.ok(req.query.sig, new HttpError('Missing required parameter: "sig"', 400));
				assert.ok(req.query.key, new HttpError('Missing required parameter: "key"', 400));
				session = map.session.get(req.query.k1);
				assert.ok(session, new HttpError('Secret does not match any known session', 400));
				const { k1, sig, key } = req.query;
				assert.ok(verifyAuthorizationSignature(sig, k1, key), new HttpError('Invalid signature', 400));
				session.lnurlAuth = session.lnurlAuth || {};
				session.lnurlAuth.linkingPublicKey = req.query.key;
				// Signature check passed.
				return new Promise((resolve, reject) => {
					return session.save(error => {
						if (error) return reject(error);
						// Overwrite the req.session object.
						// Fix when the express-session option "resave" is set to true.
						req.session = session;
						res.status(200).json({ status: 'OK' });
						resolve();
					});
				});
			}
			req.session = req.session || {};
			req.session.lnurlAuth = req.session.lnurlAuth || {};
			let k1 = req.session.lnurlAuth.k1 || null;
			if (!k1) {
				k1 = req.session.lnurlAuth.k1 = crypto.randomBytes(32).toString('hex');
				map.session.set(k1, req.session);
			}
			// Show login page.
			return this.getLoginPageHtml(k1, options).then(html => {
				res.set({
					'Content-Type': 'text/html',
					'Content-Length': Buffer.byteLength(html, 'utf8'),
				});
				return res.status(200).send(html);
			});
		}).catch(error => {
			if (!(error instanceof HttpError)) {
				debug.error(error);
				error = new HttpError('Unexpected error', 500);
			}
			return res.status(error.status).json({
				status: 'ERROR',
				reason: error.message
			});
		});
	};
};

Middleware.prototype.getLoginPageHtml = function(k1, options) {
	return Promise.resolve().then(() => {
		const callbackUrl = `${options.callbackUrl}?` + querystring.stringify({
			k1,
			tag: 'login',
		});
		const encoded = lnurl.encode(callbackUrl).toUpperCase();
		const href = `${options.uriSchemaPrefix}${encoded}`;
		return this.generateQrCode(href, options.qrcode).then(dataUri => {
			const { cancelUrl, instruction, refreshSeconds, title } = options;
			const data = Object.assign({}, {
				dataUri,
				encoded,
				href: options.uriSchemaPrefix === '' ? '#' : href,
			}, { cancelUrl, instruction, refreshSeconds, title });
			return fs.promises.readFile(options.loginTemplateFilePath).then(contents => {
				const template = handlebars.compile(contents.toString());
				return template(data);
			});
		});
	});
};

Middleware.prototype.generateQrCode = function(data, options) {
	return new Promise(function(resolve, reject) {
		QRCode.toDataURL(data, options, function(error, dataUri) {
			if (error) return reject(error);
			resolve(dataUri);
		});
	});
};

module.exports = Middleware;
