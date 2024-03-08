var Emitter = function() {
	var subscribers = {};
	return {
		on : function(eventname, callback) {
			(subscribers[eventname] = subscribers[eventname] || []).push(callback);
			return this;
		},
		emit : function(eventname) {
			var args = Array.prototype.slice.call(arguments,1);
			for (var i in subscribers[eventname]) {
				subscribers[eventname][i].apply(this, args);
			}
			return this;
		}
	};
};