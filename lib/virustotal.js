'use strict';

/* core modules */
var fs = require('fs');
var qs = require('querystring');

/* enables the usage of instanceof */
var Stream = require('stream').Stream;
var ReadStream = fs.ReadStream;
var IncomingMessage = require('http').IncomingMessage;

/* 3rd party module */
var http = require('http-request');

/* reads the package.json information */
var pack = require('../package.json');

/* internal properties */
var apiKey = '';
var vtApiEndpoint = 'https://www.virustotal.com/vtapi/v2/';
var userAgent = 'virustotal.js/v' + pack.version + ' (http://git.io/4qviFA) ' + 'node.js/' + process.version;

// Private functions

/**
 * Handles the JSON response. Decides the success / failure of the request
 *
 * @private
 */
var jsonHandler = function(buffer, callback) {
	var json, err;
	try {
		json = JSON.parse(buffer);

		if (json.response_code === 1) {
			callback(null, json);
			return;
		}

		err = new Error('The response came back with failure status.');
		err.json = json;
		callback(err);
	} catch (e) {
		callback(e);
	}
};

/**
 * Issues a GET request to the VirusTotal API
 *
 * @private
 */
var getRequest = function(method, arg, callback) {
	if (!apiKey) {
		throw new Error('The VirusTotal API requires an API key.');
	}

	arg.apikey = apiKey;

	http.get({
		url: vtApiEndpoint + method + '?' + qs.stringify(arg),
		headers: {
			'user-agent': userAgent
		}
	}, function(err, res) {
		if (err) {
			callback(err);
			return;
		}

		jsonHandler(res.buffer.toString(), callback);
	});
};

/**
 * Issues a POST request to the VirtusTotal API
 *
 * @private
 */
var postRequest = function(method, arg, callback) {
	if (!apiKey) {
		throw new Error('The VirusTotal API requires an API key.');
	}

	arg.apikey = apiKey;

	http.post({
		url: vtApiEndpoint + method,
		reqBody: new Buffer(qs.stringify(arg)),
		headers: {
			'user-agent': userAgent,
			'content-type': 'application/x-www-form-urlencoded;charset=utf-8'
		}
	}, function(err, res) {
		if (err) {
			callback(err);
			return;
		}

		jsonHandler(res.buffer.toString(), callback);
	});
};

/**
 * Wraps a POST request with multipart/form-data. Only used by scanFile
 *
 * @private
 */
var postRequestMultipart = function(resource, callback) {
	if (!apiKey) {
		throw new Error('The VirusTotal API requires an API key.');
	}

	var form = new http.FormData();
	form.append('apikey', apiKey);

	if (typeof resource === 'string') {
		form.append('file', fs.createReadStream(resource));
	}

	if (typeof resource === 'object') {
		var haveFile = false;
		if (resource.stream instanceof ReadStream) {
			form.append('file', resource.stream);
			haveFile = true;
		}

		if (resource.stream instanceof IncomingMessage) {
			var meta = {
				filename: resource.filename
			};

			if (resource.stream.headers['content-length']) {
				meta.knownLength = resource.stream.headers['content-length'];
			} else {
				meta.knownLength = resource.size;
			}

			form.append('file', resource.stream, meta);
			haveFile = true;
		}

		if (!haveFile) {
			form.append('file', resource.stream, {
				filename: resource.filename,
				knownLength: resource.size
			});
		}
	}

	http.post({
		url: vtApiEndpoint + 'file/scan',
		reqBody: form
	}, function(err, res) {
		if (err) {
			callback(err);
			return;
		}

		jsonHandler(res.buffer.toString(), callback);
	});
};

/**
 * Checks the method arguments
 *
 * @private
 */
var checkArgs = function(resource, callback, method) {
	if (!resource) {
		throw new Error('You need to define a resource argument in order to use ' + method + '().');
	}

	if (!callback || typeof callback !== 'function') {
		throw new Error('You need to define a callback for ' + method + '().');
	}
};

// Public API

/**
 * Sets the VirusTotal API key
 *
 * @param {String} key
 */
exports.setKey = function(key) {
	apiKey = String(key);
};

// VirusTotal API methods

// https://www.virustotal.com/vtapi/v2/file/scan
/**
 * Send and scan a file
 *
 * @param {Mixed} resource
 * @param {Function} callback
 */
exports.scanFile = function(resource, callback) {
	checkArgs(resource, callback, 'scanFile');
	postRequestMultipart(resource, callback);
};

// https://www.virustotal.com/vtapi/v2/file/rescan
/**
 * Rescan already submitted files
 *
 * @param {String} resource
 * @param {Function} callback
 */
exports.rescanFile = function(resource, callback) {
	checkArgs(resource, callback, 'rescanFile');
	postRequest('file/rescan', {
		resource: resource
	}, callback);
};

// https://www.virustotal.com/vtapi/v2/file/report
/**
 * Retrieve a file scan report
 *
 * @param {String} resource
 * @param {Function} callback
 *
 * @throws {resource} You need to define a resource argument in order to use getFileReport().
 * @throws {callback} You need to define a callback for getFileReport().
 */
exports.getFileReport = function(resource, callback) {
	checkArgs(resource, callback, 'getFileReport');
	postRequest('file/report', {
		resource: resource
	}, callback);
};

// https://www.virustotal.com/vtapi/v2/url/scan
/**
 * Submit and scan a URL
 *
 * @param {String} resource
 * @param {Function} callback
 */
exports.scanUrl = function(resource, callback) {
	checkArgs(resource, callback, 'scanUrl');
	postRequest('url/scan', {
		url: resource
	}, callback);
};

// http://www.virustotal.com/vtapi/v2/url/report
/**
 * Retrieve an URL scan report
 *
 * @param {String} resource
 * @param {Boolean} scan
 * @param {Function} callback
 */
exports.getUrlReport = function(resource, scan, callback) {
	if (!callback && typeof scan === 'function') {
		callback = scan;
		scan = null;
	}

	checkArgs(resource, callback, 'getUrlReport');

	var arg = {
		resource: resource
	};
	if (scan) {
		arg.scan = 1;
	}

	postRequest('url/report', arg, callback);
};

// http://www.virustotal.com/vtapi/v2/ip-address/report
/**
 * Retrieve IP address reports
 *
 * @param {String} resource
 * @param {Function} callback
 */
exports.getIpReport = function(resource, callback) {
	checkArgs(resource, callback, 'getIpReport');
	getRequest('ip-address/report', {
		ip: resource
	}, callback);
};

// http://www.virustotal.com/vtapi/v2/domain/report
/**
 * Retrieve a domain report
 *
 * @param {String} resource
 * @param {Function} callback
 */
exports.getDomainReport = function(resource, callback) {
	checkArgs(resource, callback, 'getDomainReport');
	getRequest('domain/report', {
		domain: resource
	}, callback);
};

// https://www.virustotal.com/vtapi/v2/comments/put
/**
 * Creates a new comment for file/URL
 *
 * @param {String} resource
 * @param {String} comment
 * @param {Array} tags
 * @param {Function} callback
 */
exports.makeComment = function(resource, comment, tags, callback) {
	if (!callback && typeof tags === 'function') {
		callback = tags;
		tags = null;
	}

	checkArgs(resource, callback, 'makeComment');

	if (!comment) {
		throw new Error('You need to define a comment argument in order to use makeComment().');
	}

	if (tags instanceof Array) {
		var i, tag;
		for (i in tags) {
			if (tags.hasOwnProperty(i)) {
				tag = tags[i];
				if (tag.charAt(0) !== '#') {
					tag = '#' + tag;
				}
				tags[i] = tag;
			}
		}
		comment = comment + ' ' + tags.join(' ');
	}

	postRequest('comments/put', {
		resource: resource,
		comment: comment
	}, callback);
};
