# Changelog

* v1.5.1:
  * Fix issue [#6](https://github.com/chill117/passport-lnurl-auth/issues/6) - e.g. when user authenticates with GetAlby or other ext.
  * Updated dependencies
* v1.5.0:
  * New middleware option: loginTemplateFilePath - can be used to render a custom login page
* v1.4.3:
  * Updated dependencies, removed chai and underscore
* v1.4.2:
  * Updated dependencies
* v1.4.1:
  * Updated dependencies
* v1.4.0:
  * Added new middleware options: instruction, title, refreshSeconds
  * Added footer info on login page
* v1.3.0:
  * Updated dependencies
  * New option for Middleware - "uriSchemaPrefix"
* v1.2.2:
  * Updated dependencies
  * Create, use isolated handlebars to avoid conflicts
* v1.2.1:
  * Updated dependencies
* v1.2.0:
  * Updated dependencies
* v1.1.0:
  * Updated dependencies
  * Removed secp256k1 direct dependency - using lnurl module's helper functions instead
* v1.0.1:
  * Updated dependencies
* v1.0.0:
  * Initial release
