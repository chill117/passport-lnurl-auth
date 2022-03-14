const assert = require('assert');
const express = require('express');
const helpers = require('../helpers');
const lnurl = require('lnurl');
const { generateRandomByteString, generateRandomLinkingKey } = require('lnurl/lib');
const LnurlAuth = require('../../index');
const passport = require('passport');
const querystring = require('querystring');
const session = require('express-session');
const url = require('url');

describe('express', function() {

	let app;
	before(function() {
		app = express();
		app.config = {
			host: 'localhost',
			port: 3000,
			url: 'http://localhost:3000',
		};
		app.use(session({
			secret: generateRandomByteString(20, 'base64'),
			resave: true,
			saveUninitialized: true,
		}));
		app.use(passport.initialize());
		app.use(passport.session());
		const map = {
			user: new Map(),
		};
		passport.serializeUser(function(user, done) {
			done(null, user.id);
		});
		passport.deserializeUser(function(id, done) {
			done(null, map.user.get(id) || null);
		});
		passport.use(new LnurlAuth.Strategy(function(linkingPublicKey, done) {
			let user = map.user.get(linkingPublicKey);
			if (!user) {
				user = { id: linkingPublicKey };
				map.user.set(linkingPublicKey, user);
			}
			done(null, user);
		}));
		app.use(passport.authenticate('lnurl-auth'));
		app.get('/', function(req, res) {
			if (!req.user) {
				return res.status(401).send('NOT AUTHENTICATED');
			}
			res.send('AUTHENTICATED');
		});
		app.get('/login',
			function(req, res, next) {
				if (req.user) return res.redirect('/');
				next();
			},
			new LnurlAuth.Middleware({
				callbackUrl: app.config.url + '/login',
				cancelUrl: app.config.url
			})
		);
	});

	before(function(done) {
		if (!app) return done();
		app.server = app.listen(app.config.port, app.config.host, function() {
			done();
		});
	});

	after(function(done) {
		if (!app || !app.server) return done();
		app.server.close(done);
	});

	it('login page (html)', function() {
		return helpers.request('get', {
			url:`${app.config.url}/login`,
			qs: {},
		}).then(result => {
			const { body, response } = result;
			assert.ok(response.headers['content-type']);
			assert.ok(response.headers['content-type'].indexOf('text/html') !== -1);
			assert.ok(body.indexOf('<html') !== -1);
			assert.ok(body.indexOf('<head') !== -1);
			assert.ok(body.indexOf('Login with lnurl-auth') !== -1);
			const encoded = helpers.extractEncodedFromLoginPageHtml(body);
			const dataUri = helpers.extractDataUriFromLoginPageHtml(body);
			assert.ok(dataUri.length > 250);
			const decoded = lnurl.decode(encoded);
			const parsedUrl = url.parse(decoded);
			assert.strictEqual(parsedUrl.hostname, app.config.host);
			assert.strictEqual(parseInt(parsedUrl.port), app.config.port);
			const params = querystring.parse(parsedUrl.query);
			assert.strictEqual(params.tag, 'login');
			assert.ok(params.k1);
		});
	});

	describe('whole login process', function() {

		let k1, cookie;
		before(function() {
			return helpers.request('get', {
				url:`${app.config.url}/login`,
			}).then(result => {
				const { body, response } = result;
				assert.ok(response.headers['set-cookie'][0].indexOf('connect.sid=') !== -1);
				cookie = response.headers['set-cookie'][0].split(';')[0];
				k1 = helpers.extractSecretFromLoginPageHtml(body);
			});
		});

		before(function() {
			const { sig, key } = helpers.doSigning(k1);
			const params = { k1, key, sig };
			return helpers.request('get', {
				url:`${app.config.url}/login`,
				qs: params,
				json: true,
			}).then(result => {
				const { body } = result;
				assert.deepStrictEqual(body, { status: 'OK' });
			});
		});

		it('logged-in session', function() {
			return helpers.request('get', {
				url:`${app.config.url}/`,
				headers: { cookie },
			}).then(result => {
				const { body, response } = result;
				assert.strictEqual(response.statusCode, 200);
				assert.strictEqual(body, 'AUTHENTICATED');
			});
		});

		it('logged-out (without session cookie)', function() {
			return helpers.request('get', {
				url:`${app.config.url}/`,
			}).then(result => {
				const { body, response } = result;
				assert.strictEqual(response.statusCode, 401);
				assert.strictEqual(body, 'NOT AUTHENTICATED');
			});
		})
	});

	describe('/login?k1=SECRET&sig=SIGNATURE&key=LINKINGPUBKEY', function() {

		let k1;
		before(function() {
			return helpers.request('get', {
				url:`${app.config.url}/login`,
			}).then(result => {
				const { body, response } = result;
				k1 = helpers.extractSecretFromLoginPageHtml(body);
			});
		});

		const tests = [
			{
				description: 'unknown secret',
				params: function() {
					const unknownSecret = generateRandomByteString(32, 'hex');
					const { sig, key } = helpers.doSigning(unknownSecret);
					return { k1: unknownSecret , key, sig };
				},
				expected: {
					status: 'ERROR',
					reason: 'Secret does not match any known session',
				},
			},
			{
				description: 'valid signature',
				params: function() {
					const { sig, key } = helpers.doSigning(k1);
					return { k1, key, sig };
				},
				expected: {
					status: 'OK',
				},
			},
			{
				description: 'invalid signature',
				params: function() {
					const linkingKey1 = generateRandomLinkingKey();
					const linkingKey2 = generateRandomLinkingKey();
					const { sig } = helpers.doSigning(k1, linkingKey1);
					const key = linkingKey2.pubKey.toString('hex');
					return { k1, key, sig };
				},
				expected: {
					status: 'ERROR',
					reason: 'Invalid signature',
				},
			},
		];

		['k1', 'key', 'sig'].forEach(function(requiredField) {
			tests.push({
				description: `Missing "${requiredField}"`,
				params: function() {
					const { sig, key } = helpers.doSigning(k1);
					let params = { k1, key, sig };
					delete params[requiredField];
					return params;
				},
				expected: {
					status: 'ERROR',
					reason: `Missing required parameter: "${requiredField}"`,
				},
			});
		});

		tests.forEach(function(test) {
			it(test.description, function() {
				const params = typeof test.params === 'function' ? test.params.call(this) : test.params;
				return helpers.request('get', {
					url:`${app.config.url}/login`,
					qs: params,
					json: true,
				}).then(result => {
					const { body } = result;
					assert.deepStrictEqual(body, test.expected);
				});
			});
		});
	});
});
