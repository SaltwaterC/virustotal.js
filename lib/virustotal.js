/* core modules */
var fs = require('fs');
var p = require('path');
var https = require('http');
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
	}
	var opt = {
		host: 'www.virustotal.com',
		path: '/api/' + apiMethod + '.json',
		method: 'POST',
		headers: {
			'user-agent': 'virustotal.js/v' + pack.version + ' (https://github.com/SaltwaterC/virustotal.js) ' + 'node.js/' + process.version,
		}
	};
	if (arg.file) {
		var reqBodyHead = '';
		var reqBodyTail = CRLF + '--' + BOUNDARY + '--' + CRLF;
		var file = p.resolve(arg.file);
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
	if (arg.file) {
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
 * @param arg: resource[, key]
 * @param cb
 */
var getFileReport = function (arg, cb) {
	if ( ! arg.resource) {
		cb(new Error('You need to define a resource argument in order to use getFileReport().'));
	}
	makeRequest('get_file_report', {
		resource: arg.resource,
		key: apiKey
	}, cb);
};
exports.getFileReport = getFileReport;
/**
 * Send and scan a file
 * @param arg: file[, key]
 * @param cb
 */
var scanFile = function (arg, cb) {
	if ( ! arg.file) {
		cb(new Error('You need to define a file argument in order to use scanFile().'));
	}
	makeRequest('scan_file', {
		file: arg.file,
		key: apiKey
	}, cb);
};
exports.scanFile = scanFile;

// resource, scan, key
var getUrlReport = function (arg, cb) {
	// TODO
};
exports.getUrlReport = getUrlReport;

// url, key
var scanUrl = function (arg, cb) {
	// TODO
};
exports.scanUrl = scanUrl;

// file|url, comment, tags, key
var makeComment = function (arg, cb) {
	if ( ! arg.file && ! arg.url) {
		cb(new Error('You must use one of the resource identifiers to make a comment: file or url.'));
		return;
	}
	if (arg.file && arg.url) {
		cb(new Error('You must use either file or url for making a comment. Not both.'));
		return;
	}
	if (arg.file && arg.tags) { // validate file tags
		// TODO
	}
	
	if (arg.url && arg.tags) { // validate url tags
		// TODO
	}
	
	// TODO
};
exports.makeComment = makeComment;
