let Store = function() {
	this.map = new Map();
};

Store.prototype.get = function(k1) {
	return Promise.resolve().then(() => {
		return this.map.get(k1);
	});
};

Store.prototype.save = function(k1, session) {
	return Promise.resolve().then(() => {
		return this.map.set(k1, session);
	});
};

module.exports = Store;
