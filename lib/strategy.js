const passport = require('passport-strategy');
const util = require('util');

const Strategy = function(verify) {
	if (!verify || typeof verify !== 'function') {
		throw new TypeError('LnurlAuthStrategy requires a verify callback');
	}
	passport.Strategy.call(this);
	this.name = 'lnurl-auth';
	this._verify = verify;
};

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {
	try {
		const linkingPublicKey = req.session.lnurlAuth && req.session.lnurlAuth.linkingPublicKey;
		if (linkingPublicKey) {
			return this._verify(linkingPublicKey, (error, user, info) => {
				if (error) return this.error(error);
				if (!user) return this.fail(info);
				this.success(user, info);
			});
		}
	} catch (error) {
		return this.error(error);
	}
	this.pass();
};

module.exports = Strategy;
