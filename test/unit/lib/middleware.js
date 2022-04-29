const assert = require('assert');
const { Middleware } = require('../../../');
const path = require('path');

describe('Middleware', function() {

	describe('loginTemplateFilePath', function() {

		it('file does not exist', function() {
			assert.throws(() => {
				new Middleware({
					callbackUrl: 'http://localhost:3000/login',
					loginTemplateFilePath: path.join(__dirname, '..', '..', 'templates', 'does-not-exist.html'),
				});
			}, {
				message: 'Invalid middleware option ("loginTemplateFilePath"): Cannot open login.html template file: Does not exist',
			});
		});
	});
});
