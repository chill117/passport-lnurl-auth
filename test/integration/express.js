const _ = require('underscore');
const { expect } = require('chai');
const express = require('express');
const helpers = require('../helpers');
const lnurl = require('lnurl');
const { generateRandomLinkingKey } = lnurl;
const { generateRandomByteString } = require('lnurl/lib');
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

	it('login page (html)', function(done) {
		helpers.request('get', {
			url: app.config.url + '/login',
			qs: {},
		}, function(error, response, body) {
			if (error) return done(error);
			try {
				expect(response.headers['content-type']).to.not.be.undefined;
				expect(response.headers['content-type']).to.have.string('text/html');
				expect(body).to.have.string('<html');
				expect(body).to.have.string('<head');
				expect(body).to.have.string('Login with lnurl-auth');
				const encoded = helpers.extractEncodedFromLoginPageHtml(body);
				const dataUri = helpers.extractDataUriFromLoginPageHtml(body);
				expect(dataUri.length > 250);
				const decoded = lnurl.decode(encoded);
				const parsedUrl = url.parse(decoded);
				expect(parsedUrl.hostname).to.equal(app.config.host);
				expect(parseInt(parsedUrl.port)).to.equal(app.config.port);
				const params = querystring.parse(parsedUrl.query);
				expect(params.tag).to.equal('login');
				expect(params.k1).to.not.be.undefined;
			} catch (error) {
				return done(error);
			}
			done();
		});
	});

	describe('whole login process', function() {

		let k1, cookie;
		before(function(done) {
			helpers.request('get', {
				url: app.config.url + '/login',
			}, function(error, response, body) {
				if (error) return done(error);
				try {
					expect(response.headers['set-cookie'][0]).to.have.string('connect.sid=');
					cookie = response.headers['set-cookie'][0].split(';')[0];
					k1 = helpers.extractSecretFromLoginPageHtml(body);
				} catch (error) {
					return done(error);
				}
				done();
			});
		});

		before(function(done) {
			const { sig, key } = helpers.doSigning(k1);
			const params = { k1, key, sig };
			helpers.request('get', {
				url: app.config.url + '/login',
				qs: params,
				json: true,
			}, function(error, response, body) {
				if (error) return done(error);
				try {
					expect(body).to.deep.equal({ status: 'OK' });
				} catch (error) {
					return done(error);
				}
				done();
			});
		});

		it('logged-in session', function(done) {
			helpers.request('get', {
				url: app.config.url + '/',
				headers: { cookie },
			}, function(error, response, body) {
				if (error) return done(error);
				try {
					expect(response.statusCode).to.equal(200);
					expect(body).to.equal('AUTHENTICATED');
				} catch (error) {
					return done(error);
				}
				done();
			});
		});

		it('logged-out (without session cookie)', function(done) {
			helpers.request('get', {
				url: app.config.url + '/',
			}, function(error, response, body) {
				if (error) return done(error);
				try {
					expect(response.statusCode).to.equal(401);
					expect(body).to.equal('NOT AUTHENTICATED');
				} catch (error) {
					return done(error);
				}
				done();
			});
		})
	});

	describe('/login?k1=SECRET&sig=SIGNATURE&key=LINKINGPUBKEY', function() {

		let k1;
		before(function(done) {
			helpers.request('get', {
				url: app.config.url + '/login',
			}, function(error, response, body) {
				if (error) return done(error);
				try {
					k1 = helpers.extractSecretFromLoginPageHtml(body);
				} catch (error) {
					return done(error);
				}
				done();
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

		_.each(['k1', 'key', 'sig'], function(requiredField) {
			tests.push({
				description: `Missing "${requiredField}"`,
				params: function() {
					const { sig, key } = helpers.doSigning(k1);
					return _.omit({ k1, key, sig }, requiredField);
				},
				expected: {
					status: 'ERROR',
					reason: `Missing required parameter: "${requiredField}"`,
				},
			});
		});

		_.each(tests, function(test) {
			it(test.description, function(done) {
				const params = _.isFunction(test.params) ? test.params.call(this) : test.params;
				helpers.request('get', {
					url: app.config.url + '/login',
					qs: params,
					json: true,
				}, function(error, response, body) {
					if (error) return done(error);
					try {
						expect(body).to.deep.equal(test.expected);
					} catch (error) {
						return done(error);
					}
					done();
				});
			});
		});
	});
});
