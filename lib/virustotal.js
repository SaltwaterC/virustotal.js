'use strict';

/**
 * @module virustotal
 */

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
var ak = '';
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

	if ((buffer instanceof Buffer) !== true) {
		err = new Error('The returned response contains no data. Most probably you\'ve hit an API quota limit.');
		callback(err);
		return;
	}

	buffer = buffer.toString();

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
	if (!ak) {
		throw new Error('The VirusTotal API requires an API key.');
	}

	arg.apikey = ak;

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

		jsonHandler(res.buffer, callback);
	});
};

/**
 * Issues a POST request to the VirtusTotal API
 *
 * @private
 */
var postRequest = function(method, arg, callback) {
	if (!ak) {
		throw new Error('The VirusTotal API requires an API key.');
	}

	arg.apikey = ak;

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

		jsonHandler(res.buffer, callback);
	});
};

/**
 * Wraps a POST request with multipart/form-data. Only used by scanFile
 *
 * @private
 */
var postRequestMultipart = function(resource, callback) {
	if (!ak) {
		throw new Error('The VirusTotal API requires an API key.');
	}

	var form = new http.FormData();
	form.append('apikey', ak);

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
			var meta = {};

			if (resource.filename) {
				meta.filename = resource.filename;
			}

			if (resource.size) {
				meta.knownLength = resource.size;
			} else if (resource.stream.headers['content-length']) {
				meta.knownLength = resource.stream.headers['content-length'];
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
		reqBody: form,
		headers: {
			'user-agent': userAgent
		}
	}, function(err, res) {
		if (err) {
			callback(err);
			return;
		}

		jsonHandler(res.buffer, callback);
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
 * @param {String} apiKey VirusTotal API key
 *
 * @example
// it is mandatory to call this before any other remote calls to the VirusTotal API
virustotal.setKey('your-virustotal-api-key');
 */
exports.setKey = function(apiKey) {
	ak = String(apiKey);
};

// VirusTotal API methods

// https://www.virustotal.com/vtapi/v2/file/scan
/**
 * Send and scan a file
 *
 * @param {Mixed} resource - a String for a disk path or a {@link module:virustotal~streamWrapper}
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {Mixed} You need to define a resource argument in order to use scanFile().
 * @throws {module:virustotal~callback} You need to define a callback for scanFile().
 *
 * @example
// scan a file stored to disk
virustotal.scanFile('/path/to/file', function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});

// wrapping a ReadStream created with fs.createReadStream
virustotal.scanFile({
	stream: fs.createReadStream('/path/to/file')
}, function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});

// wrapping an IncomingMessage (a HTTP response)
http.get('http://example.org/file.exe', function (im) {
	virustotal.scanFile({
		stream: im,
		// you may specify a filename
		// the form-data library may detect it from the IncomingMessage
		// but this could produce the wrong filename
		// your call
		filename: 'file.exe'
	}, function (err, res) {
		if (err) {
			console.error(err);
			return;
		}
		
		console.log(res);
	});
});

// wrapping a generic stream
// in this case you need to specify both the filename and the size of the stream
virustotal.scanFile({
	stream: readableStream,
	filename: 'filename.exe',
	size: 1337
}, function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});
 */
exports.scanFile = function(resource, callback) {
	checkArgs(resource, callback, 'scanFile');
	postRequestMultipart(resource, callback);
};

// https://www.virustotal.com/vtapi/v2/file/rescan
/**
 * Rescan already submitted files
 *
 * @param {module:virustotal~virustotalResource} resource A VirusTotal resource. The CSV list may have up to 25 items
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {module:virustotal~virustotalResource} You need to define a resource argument in order to use rescanFile().
 * @throws {module:virustotal~callback} You need to define a callback for rescanFile().
 *
 * @example
virustotal.rescanFile(
	'2fc19a61b81055c199f23de35b7eb8b2827e283442965bc1898c0e044563d836',
	function (err, res) {
		if (err) {
			console.error(err);
			return;
		}
		
		console.log(res);
	}
);
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
 * @param {module:virustotal~virustotalResource} resource A VirusTotal resource. The CSV list may have up to 4 items
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {module:virustotal~virustotalResource} You need to define a resource argument in order to use getFileReport().
 * @throws {module:virustotal~callback} You need to define a callback for getFileReport().
 *
 * @example
virustotal.getFileReport(
	'2fc19a61b81055c199f23de35b7eb8b2827e283442965bc1898c0e044563d836',
	function (err, res) {
		if (err) {
			console.error(err);
			return;
		}
		
		console.log(res);
	}
);
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
 * @param {String} resource An URL or a CSV list of up to 4 URLs
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {String} You need to define a resource argument in order to use scanUrl().
 * @throws {module:virustotal~callback} You need to define a callback for scanUrl().
 *
 * @example
virustotal.scanUrl('http://example.org/', function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});
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
 * @param {String} resource An URL, a scan_id returned by {@link module:virustotal.scanUrl}, or a CSV list made of URLs and scan_ids. The CSV list may have up to 4 items
 * @param {Boolean} scan Optional; Set this to true to scan the URL if no report is found for it in VirusTotal's database
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {String} You need to define a resource argument in order to use getUrlReport().
 * @throws {module:virustotal~callback} You need to define a callback for getUrlReport().
 *
 * @example
virustotal.getUrlReport('http://example.org/', function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});
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
 * Retrieve IP address report
 *
 * @param {String} resource An IPv4 address
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {String} You need to define a resource argument in order to use getIpReport().
 * @throws {module:virustotal~callback} You need to define a callback for getIpReport().
 *
 * @example
virustotal.getIpReport('8.8.8.8', function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});
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
 * @param {String} resource Domain name
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {String} You need to define a resource argument in order to use getDomainReport().
 * @throws {module:virustotal~callback} You need to define a callback for getDomainReport().
 *
 * @example
virustotal.getDomainReport('example.org', function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
});
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
 * @param {String} resource A {@link module:virustotal~virustotalResource} or URL submitted via {@link module:virustotal.scanUrl}
 * @param {String} comment The comment
 * @param {Array} tags Optional; List of tags to prepend to the comment
 * @param {module:virustotal~callback} callback Completion callback
 *
 * @throws {String} You need to define a resource argument in order to use makeComment().
 * @throws {module:virustotal~callback} You need to define a callback for makeComment().
 *
 * @example
virustotal.makeComment(
	'2fc19a61b81055c199f23de35b7eb8b2827e283442965bc1898c0e044563d836',
	'Yahoo! Messenger installer.',
	['goodware', 'clean'],
	function (err, res) {
		if (err) {
			console.error(err);
			return;
		}
		
		console.log(res);
	}
);
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

// Documentation section

/**
 * The completion callback
 *
 * @callback module:virustotal~callback
 * @param {module:virustotal~error} error The passed error or *null* on success
 * @param {module:virustotal~result} result The VirusTotal report or confirmation for succesful action
 */

/**
 * The result Object which is obtained by parsing the JSON response of the VirusTotal API. The result is passed to the success case only when its response_code equals to 1
 *
 * @typedef module:virustotal~result
 * @type {Object}
 */

/**
 * The Error instance describing what went wrong. There are three types of errors. 1. A HTTP error which may happen under the conditions described by the [Response basics](https://www.virustotal.com/en/documentation/public-api/#response-basics), handled by the http-request library's [stdError object](http://saltwaterc.github.io/http-request/module-request.html#stdError). 2. If the JSON is corrupt, then the error is defined by the exception thrown by [JSON.parse](http://es5.github.io/#x15.12). 3. The last case of error is when the response_code property of the returned JSON does not equal to 1
 *
 * @typedef module:virustotal~error
 * @type {Error}
 * @property {Object} json Defined when the parsed JSON has the response_code property different than 1. Contains the response from the VirusTotal API describing what went wrong. error.json.verbose_msg describes the error in detail
 */

/**
 * md5/sha1/sha256 file hash, a scan_id (sha256-timestamp as returned by {@link module:virustotal.scanFile}), or a CSV list made of a combination of hashes and scan_ids
 *
 * @typedef module:virustotal~virustotalResource
 * @type {String}
 */

/**
 * The stream wrapper for uploading a file to the VirusTotal API by using {@link module:virustotal.scanFile}
 *
 * @typedef module:virustotal~streamWrapper
 * @type {Object}
 * @property {Object} stream Mandatory; The Readable Stream instance
 * @property {String} filename Optional; The file name of the resource. This property recommended for streams that are a [http.IncommingMessage](http://nodejs.org/api/http.html#http_http_incomingmessage), and mandatory for generic Readable Streams
 * @property {Number} size Optional; The size of the stream. It is mandatory to define this property for streams with unknown length. This includes a http.IncomingMessage that uses chunked transfer which does not pass a content-length header. The content-lenght header value is used only when the size property is undefined. Compressed responses with gzip or deflate provide a wrong value for the size property, therefore it is recommended to avoid using HTTP compression if you wish to use the content-length value
 */