# passport-lnurl-auth

![Build Status](https://github.com/chill117/passport-lnurl-auth/actions/workflows/ci.yml/badge.svg)

A passport strategy for [lnurl-auth](https://github.com/btcontract/lnurl-rfc/blob/master/lnurl-auth.md).

* [Installation](#installation)
* [Usage](#usage)
	* [Debugging](#debugging)
	* [Remote Tunneling](#remote-tunneling)
		* [Using SSH and a VPS](#using-ssh-and-a-vps)
		* [Using ngrok](#using-ngrok)
* [Changelog](#changelog)
* [License](#license)
* [Funding](#funding)


## Installation

Add to your application via `npm`:
```
npm install passport-lnurl-auth --save
```
This will install the module and add it to your application's `package.json` file.


## Usage

```js
const LnurlAuth = require('passport-lnurl-auth');

passport.use(new LnurlAuth.Strategy(function(linkingPublicKey, done) {
	// The user has successfully authenticated using lnurl-auth.
	// The linked public key is provided here.
	// You can use this as a unique reference for the user similar to a username or email address.
	const user = { id: linkingPublicKey };
	done(null, user);
}));

app.use(passport.authenticate('lnurl-auth'));

app.get('/', function(req, res) {
	if (!req.user) {
		return res.send('You are not authenticated. To login go <a href="/login">here</a>.');
	}
	res.send('Logged-in');
});

app.get('/login',
	function(req, res, next) {
		if (req.user) {
			return res.redirect('/');
		}
		next();
	},
	new LnurlAuth.Middleware({
		// The externally reachable URL for the lnurl-auth middleware.
		// It should resolve to THIS endpoint on your server.
		callbackUrl: 'http://localhost:3000/login',
		// The URL of the "Cancel" button on the login page.
		// When set to NULL or some other falsey value, the cancel button will be hidden.
		cancelUrl: '/',
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
		// Options object passed to QRCode.toDataURL(data, options) - for further details:
		// https://github.com/soldair/node-qrcode/#qr-code-options
		qrcode: {
			errorCorrectionLevel: 'L',
			margin: 2,
			type: 'image/png',
		},
	})
);
```
For a complete, working example see the [simple server](https://github.com/chill117/passport-lnurl-auth/blob/master/examples/simple.js) included with this project.

To test the end-to-end login flow with lnurl-auth, see [Remote Tunneling](#remote-tunneling).


### Debugging

This module uses the [debug module](https://github.com/visionmedia/debug). To output all debug messages to the console, run your node app with the `DEBUG` environment variable:
```
DEBUG=passport-lnurl-auth* node your-app.js
```
This will output log messages as well as error messages related to this module.



### Remote Tunneling

While working locally, your web application will need to be accessible by the mobile app that you will use to perform the lnurl-auth authentication. This means that the web app must be reachable from the public internet. To achieve this, you can configure remote tunneling to your localhost. There are a few ways that this can be done.

#### Using SSH and a VPS

You can use this method if you already have a virtual private server (VPS) with its own static, public IP address.

Login to your VPS and add a few required configurations to its SSH config file:
```bash
cat >> /etc/ssh/sshd_config << EOL
    RSAAuthentication yes
    PubkeyAuthentication yes
    GatewayPorts yes
    AllowTcpForwarding yes
    ClientAliveInterval 60
    EOL
```
Restart the SSH service:
```bash
service ssh restart
```
On your local machine, run the following command to open a reverse-proxy tunnel:
```bash
ssh -v -N -T -R 3000:localhost:3000 VPS_HOST_OR_IP_ADDRESS
```
This will forward all traffic to port 3000 to the VPS thru the SSH tunnel to port 3000 on your local machine.

Provide the VPS IP address + endpoint path as the `callbackUrl` option. For example:
```js
app.get('/login',
	function(req, res, next) {
		if (req.user) {
			return res.redirect('/');
		}
		next();
	},
	new LnurlAuth.Middleware({
		callbackUrl: 'http://VPS_IP_ADDRESS:3000/login'
	})
);
```
Be sure to replace `VPS_IP_ADDRESS` with the actual IP address of your server.


#### Using ngrok

If you don't have access to your own VPS, [ngrok](https://ngrok.com/) is another possible solution. Follow the installation instructions on the project's website before continuing here. Once you have ngrok installed, you can continue with the instructions here.

To create an HTTP tunnel:
```bash
ngrok http -region eu 3000
```
You should see something like the following:

![](https://github.com/chill117/passport-lnurl-auth/blob/master/images/ngrok-screen-https-tunnel.png)

Provide the HTTPS tunnel URL + endpoint path as the `callbackUrl` option. For example:
```js
app.get('/login',
	function(req, res, next) {
		if (req.user) {
			return res.redirect('/');
		}
		next();
	},
	new LnurlAuth.Middleware({
		callbackUrl: 'https://a9453568.eu.ngrok.io/login'
	})
);
```
Note that each time you open a tunnel with ngrok, your tunnel URL changes. 


## Changelog

See [CHANGELOG.md](https://github.com/chill117/passport-lnurl-auth/blob/master/CHANGELOG.md)


## License

This software is [MIT licensed](https://tldrlegal.com/license/mit-license):
> A short, permissive software license. Basically, you can do whatever you want as long as you include the original copyright and license notice in any copy of the software/source.  There are many variations of this license in use.


## Funding

This project is free and open-source. If you would like to show your appreciation by helping to fund the project's continued development and maintenance, you can find available options [here](https://degreesofzero.com/donate.html?project=passport-lnurl-auth).
