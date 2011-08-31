## About

VirusTotal API client for node.js.

## Installation

Either manually clone this repository into your node_modules directory, or the recommended method:

> npm install virustotal.js

## Reference

> setKey(key) - Set the [VirusTotal API key](https://www.virustotal.com/vt-community/inbox.html).

 * key      => string containing the API key

> getFileReport(resource, callback) - Retrieve a file scan report

 * resource => md5 | sha1 | sha256 | sha256-timestamp identifier
 * callback => (errror, result)

> scanFile(file, callback) - Send and scan a file

 * file     => path to the file to be uploaded
 * callback => (errror, result)

> getUrlReport(resource, [scan], callback) - Retrieve an URL scan report

 * resource => URL | md5-timestamp identifier
 * scan     => [optional] when set to "1" will automatically submit the URL for analysis if no report is found
 * callback => (errror, result)

> scanUrl(url, callback) - Submit and scan an URL

 * url      => URL that should be scanned
 * callback => (errror, result)

> makeFileComment(fileHash, comment, [tags], callback) - Make comments on files

 * fileHash => md5 | sha1 | sha256 of the file that you want to comment on
 * comment  => the actual comment
 * tags     => [optional] array containing the list of tags
 * callback => (errror, result)

> makeUrlComment(url, comment, [tags], callback) - Make comments on URLs

 * url      => the URL itself that you want to comment on
 * comment  => the actual comment
 * tags     => [optional] array containing the list of tags
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

## Error Handling

Unless there's a coding error, the library returns the error as the error argument of the callback. Otherwise it throws Error()s. Except the tags for the comments, there's no syntax validation before sending the arguments to the VirusTotal API. Validating the input before sending it (such as checking that a hash has a proper syntax) is planned, but it has low priority on my TODO list.
