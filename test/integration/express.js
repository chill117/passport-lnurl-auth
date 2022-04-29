const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const lnurl = require('lnurl');
const { generateRandomLinkingKey } = require('lnurl/lib');
const LnurlAuth = require('../../index');
const passport = require('passport');
const path = require('path');
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
			secret: crypto.randomBytes(20).toString('base64'),
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
		return this.helpers.request('get', {
			url:`${app.config.url}/login`,
			qs: {},
		}).then(result => {
			const { body, response } = result;
			assert.ok(response.headers['content-type']);
			assert.ok(response.headers['content-type'].indexOf('text/html') !== -1);
			assert.ok(body.indexOf('<html') !== -1);
			assert.ok(body.indexOf('<head') !== -1);
			assert.ok(body.indexOf('Login with lnurl-auth') !== -1);
			const encoded = this.helpers.extractEncodedFromLoginPageHtml(body);
			const dataUri = this.helpers.extractDataUriFromLoginPageHtml(body);
			assert.ok(dataUri.length > 250);
			const decoded = lnurl.decode(encoded);
			const parsedUrl = url.parse(decoded, true);
			assert.strictEqual(parsedUrl.hostname, app.config.host);
			assert.strictEqual(parseInt(parsedUrl.port), app.config.port);
			const { query } = parsedUrl;
			assert.strictEqual(query.tag, 'login');
			assert.ok(query.k1);
		});
	});

	describe('whole login process', function() {

		let k1, cookie;
		before(function() {
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
			}).then(result => {
				const { body, response } = result;
				assert.ok(response.headers['set-cookie'][0].indexOf('connect.sid=') !== -1);
				cookie = response.headers['set-cookie'][0].split(';')[0];
				k1 = this.helpers.extractSecretFromLoginPageHtml(body);
			});
		});

		before(function() {
			const { sig, key } = this.helpers.doSigning(k1);
			const query = { k1, key, sig };
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
				qs: query,
			}).then(result => {
				const { body } = result;
				assert.deepStrictEqual(body, { status: 'OK' });
			});
		});

		it('logged-in session', function() {
			return this.helpers.request('get', {
				url:`${app.config.url}/`,
				headers: { cookie },
			}).then(result => {
				const { body, response } = result;
				assert.strictEqual(response.statusCode, 200);
				assert.strictEqual(body, 'AUTHENTICATED');
			});
		});

		it('logged-out (without session cookie)', function() {
			return this.helpers.request('get', {
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
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
			}).then(result => {
				const { body, response } = result;
				k1 = this.helpers.extractSecretFromLoginPageHtml(body);
			});
		});

		it('unknown secret', function() {
			const unknownSecret = crypto.randomBytes(32).toString('hex');
			const { sig, key } = this.helpers.doSigning(unknownSecret);
			const query = { k1: unknownSecret, key, sig };
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
				qs: query,
			}).then(result => {
				const { body } = result;
				assert.deepStrictEqual(body, {
					status: 'ERROR',
					reason: 'Secret does not match any known session',
				});
			});
		});

		it('invalid signature', function() {
			const linkingKey1 = generateRandomLinkingKey();
			const linkingKey2 = generateRandomLinkingKey();
			const { sig } = this.helpers.doSigning(k1, linkingKey1);
			const key = linkingKey2.pubKey.toString('hex');
			const query = { k1, key, sig };
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
				qs: query,
			}).then(result => {
				const { body } = result;
				assert.deepStrictEqual(body, {
					status: 'ERROR',
					reason: 'Invalid signature',
				});
			});
		});

		it('valid signature', function() {
			const { sig, key } = this.helpers.doSigning(k1);
			const query = { k1, key, sig };
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
				qs: query,
			}).then(result => {
				const { body } = result;
				assert.deepStrictEqual(body, {
					status: 'OK',
				});
			});
		});

		['k1', 'key', 'sig'].forEach(requiredField => {
			it(`Missing "${requiredField}"`, function() {
				const { sig, key } = this.helpers.doSigning(k1);
				let query = { k1, key, sig };
				delete query[requiredField];
				return this.helpers.request('get', {
					url:`${app.config.url}/login`,
					qs: query,
				}).then(result => {
					const { body } = result;
					assert.deepStrictEqual(body, {
						status: 'ERROR',
						reason: `Missing required parameter: "${requiredField}"`,
					});
				});
			});
		});
	});

	describe('loginTemplateFilePath', function() {

		let app;
		before(function() {
			app = express();
			app.config = {
				host: 'localhost',
				port: 3001,
				url: 'http://localhost:3001',
			};
			app.get('/login',
				function(req, res, next) {
					if (req.user) return res.redirect('/');
					next();
				},
				new LnurlAuth.Middleware({
					callbackUrl: app.config.url + '/login',
					loginTemplateFilePath: path.join(__dirname, '..', 'templates', 'login.html'),
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

		it('custom login.html should be used', function() {
			return this.helpers.request('get', {
				url:`${app.config.url}/login`,
			}).then(result => {
				const { body } = result;
				assert.strictEqual(body, '<html><head><title>Custom login.html</head><body><p>Custom login page</p></body></html>');
			});
		});
	});
});
