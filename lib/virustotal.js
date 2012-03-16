/* core modules */
var fs = require('fs');
var p = require('path');
var https = require('https');
var qs = require('querystring');
/* reads the package.json information */
var pack = JSON.parse(fs.readFileSync(p.resolve(__dirname + '/../package.json')).toString('utf8'));
/* internal properties */
var CRLF = '\r\n';
var BOUNDARY = 'virustotal--js';
var apiKey = '';
/**
 * Sets the VirusTotal API key
 * @param key
 */
var setKey = function (key) {
	apiKey = String(key);
};
exports.setKey = setKey;
/**
 * Encodes a field part of a multipart/form-data
 * @param name
 * @param value
 * @return string
 */
var encodeFieldPart = function (name, value) {
	var fieldPart = '--' + BOUNDARY + CRLF;
	fieldPart += 'content-disposition: form-data; name="' + name + '"' + CRLF + CRLF;
	fieldPart += value + CRLF;
	return fieldPart;
};
/**
 * Encodes a file part of a multipart/form-data
 * @param type
 * @param name
 * @param filename
 * @return string
 */
var encodeFilePart = function (type, name, filename) {
	var filePart = '--' + BOUNDARY + CRLF;
	filePart += 'content-disposition: form-data; name="' + name + '"; filename="' + filename + '"' + CRLF;
	filePart += 'content-type: ' + type + CRLF + CRLF;
	return filePart;
};
/**
 * Makes the HTTPS POST request to the VirusTotal API
 * @param apiMethod
 * @param arg
 * @param cb
 */
var makeRequest = function (apiMethod, arg, cb) {
	if ( ! apiKey) {
		throw new Error('The VirusTotal API requires an API key.');
	} else {
		arg.apikey = apiKey;
	}
	var opt = {
		host: 'www.virustotal.com',
		path: '/vtapi/v2/' + apiMethod,
		method: 'POST',
		headers: {
			'user-agent': 'virustotal.js/v' + pack.version + ' (https://github.com/SaltwaterC/virustotal.js) ' + 'node.js/' + process.version
		}
	};
	if (arg.upFile) {
		var reqBodyHead = '';
		var reqBodyTail = CRLF + '--' + BOUNDARY + '--' + CRLF;
		var file = p.resolve(arg.upFile);
		for (var i in arg) {
			if (i != 'file') {
				reqBodyHead += encodeFieldPart(i, arg[i]);
			}
		}
		reqBodyHead += encodeFilePart('application/octet-stream', 'file', p.basename(file));
		try {
			var fileLength = fs.statSync(file).size;
		} catch (e) {
			cb(e);
			return;
		}
		opt.headers['content-type'] = 'multipart/form-data; boundary=' + BOUNDARY;
		opt.headers['content-length'] = reqBodyHead.length + fileLength + reqBodyTail.length;
	} else {
		var reqBody = qs.stringify(arg);
		opt.headers['content-type'] = 'application/x-www-form-urlencoded; charset=utf-8';
		opt.headers['content-length'] = reqBody.length;
	}
	var req = https.request(opt, function (res) {
		var body = '';
		res.on('data', function (data) {
			body += data;
		});
		res.on('end', function () {
			var json = false;
			try {
				json = JSON.parse(body);
			} catch (err) {}
			
			if (res.statusCode == 200) { // success
				if (json) {
					cb(null, json);
				} else {
					cb(err);
				}
			} else { // failure
				var err = new Error('HTTP Error ' + res.statusCode);
				err.code = res.statusCode;
				if (json) {
					err.content = json;
				} else {
					err.content = body;
				}
				cb(err);
			}
		});
	});
	req.on('error', function (err) {
		cb(err);
	});
	if (arg.upFile) {
		var aborted = false;
		req.write(reqBodyHead);
		var rs = fs.createReadStream(file);
		rs.on('error', function (err) {
			aborted = true;
			req.abort();
			cb(err);
		});
		rs.on('data', function (data) {
			if ( ! aborted) {
				req.write(data);
			}
		});
		rs.on('end', function () {
			if ( ! aborted) {
				req.write(reqBodyTail);
				req.end();
			}
		});
	} else {
		req.write(reqBody);
		req.end();
	}
};
/**
 * Retrieve a file scan report
 * @param resource
 * @param cb
 */
var getFileReport = function (resource, cb) {
	if ( ! resource) {
		throw new Error('You need to define a resource argument in order to use getFileReport().');
	}
	makeRequest('file/report', {resource: resource}, cb);
};
exports.getFileReport = getFileReport;
/**
 * Send and scan a file
 * @param file
 * @param cb
 */
var scanFile = function (file, cb) {
	if ( ! file) {
		throw new Error('You need to define a file argument in order to use scanFile().');
	}
	if ( ! cb || typeof cb != 'function') {
		throw new Error('You need to define a callback for getUrlReport().');
	}
	makeRequest('file/scan', {upFile: file}, cb);
};
exports.scanFile = scanFile;
/**
 * Retrieve a URL scan report
 * @param resource
 * @param scan
 * @param cb
 */
var getUrlReport = function (resource, scan, cb) {
	if ( ! resource) {
		throw new Error('You need to define a resource argument in order to use getUrlReport().');
	}
	if ( ! cb && typeof scan == 'function') {
		cb = scan;
		scan = null;
	}
	if ( ! cb || typeof cb != 'function')
	{
		throw new Error('You need to define a callback for getUrlReport().');
	}
	var arg = {resource: resource};
	if (scan) {
		arg.scan = 1;
	}
	makeRequest('url/report', arg, cb);
};
exports.getUrlReport = getUrlReport;
/**
 * Submit and scan a URL
 * @param url
 * @param cb
 */
var scanUrl = function (url, cb) {
	if ( ! url) {
		throw new Error('You need to define an url argument in order to use scanUrl().');
	}
	if ( ! cb || typeof cb != 'function')
	{
		throw new Error('You need to define a callback for scanUrl().');
	}
	makeRequest('url/scan', {url: url}, cb);
};
exports.scanUrl = scanUrl;
/**
 * Creates a new comment for file/URL
 * @param resource
 * @param comment
 * @param tags
 * @param cb
 */
var makeComment = function (resource, comment, tags, cb) {
	if ( ! comment) {
		throw new Error('You need to define a comment argument in order to use makeComment().');
	}
	if ( ! cb && typeof tags == 'function') {
		cb = tags;
		tags = null;
	}
	if ( ! cb || typeof cb != 'function') {
		throw new Error('You need to define a callback for ' + method + '().');
	}
	if (tags) {
		for (var i in tags) {
			var tag = tags[i];
			if (tag.charAt(0) != '#') {
				tag = '#' + tag;
			}
			tags[i] = tag;
		}
		comment = comment + ' ' + tags.join(' ');
	}
	makeRequest('comments/put', {resource: resource, comment: comment}, cb);
};
exports.makeComment = makeComment;
/**
 * makeComment wrapper for the old method
 * @param fileHash
 * @param comment
 * @param tags
 * @param cb
 */
var makeFileComment = function (fileHash, comment, tags, cb) {
	console.error('Warning: the usage of makeFileComment() is deprecated in favor of makeComment().');
	makeRequest.apply(this, arguments);
};
exports.makeFileComment = makeFileComment;
/**
 * makeComment wrapper for the old method
 * @param url
 * @param comment
 * @param tags
 * @param cb
 */
var makeUrlComment = function (url, comment, tags, cb) {
	console.error('Warning: the usage of makeUrlComment() is deprecated in favor of makeComment().');
	makeRequest.apply(this, arguments);
};
exports.makeUrlComment = makeUrlComment;
