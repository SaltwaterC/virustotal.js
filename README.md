## About

VirusTotal API client for node.js. Currently under development and somehow usable.

## Reference

> setKey(key) - Set the VirusTotal API key.
 * key => string containing the API key

> getFileReport(resource, callback) - Retrieve a file scan report
 * resource => md5 | sha1 | sha256 | sha256-timestamp identifier
 * callback => (errror, result)

> scanFile(file, callback) - Send and scan a file
 * file     => path to the file to be uploaded
 * callback => (errror, result)

> getUrlReport(resource, [scan], callback) - Retrieve a URL scan report
 * resource => URL | md5-timestamp identifier
 * scan     => [optional] when set to "1" will automatically submit the URL for analysis if no report is found
 * callback => (errror, result)

> scanUrl(url, callback) - Submit and scan a URL
 * url      => URL that should be scanned
 * callback => (errror, result)

## Usage mode

```javascript
var vt = require('virustotal.js'); // need to be in node_modules to work like this
vt.setKey('your-api-key');
vt.scanFile('/path/to/file.foo.bar', function (err, res) {
	if (err) {
		console.error(err);
	} else {
		console.log(res);
	}
});
```

## Currently Not Implemented

 * make_comment
