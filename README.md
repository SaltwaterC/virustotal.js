## About ![stillmaintained](http://stillmaintained.com/SaltwaterC/virustotal.js.png)

VirusTotal API client for node.js.

## Installation

Either manually clone this repository into your node_modules directory, or the recommended method:

> npm install virustotal.js

## Reference

> setKey(key) - Set the VirusTotal API key.

 * key      => string containing the API key

> getFileReport(resource, callback) - Retrieve a file scan report

 * resource => md5 | sha1 | sha256 | sha256-timestamp identifier aka scan_id | CVS list made up of a combination of hashes and scan_ids
 * callback => (errror, result)

> scanFile(streamWrapper, callback) - Send and scan a file

 * streamWrapper => an object containing the following keys: filename (the original file name), size (the size of the stream, in bytes), stream (the Readable Stream instance)
 * callback      => (errror, result)

> getUrlReport(resource, [scan], callback) - Retrieve an URL scan report

 * resource => URL | sha256-timestamp identifier aka scan_id | CSV list made up of a combination of hashes and scan_ids
 * scan     => [optional] when set to "1" will automatically submit the URL for analysis if no report is found
 * callback => (errror, result)

> scanUrl(url, callback) - Submit and scan an URL

 * url      => URL to be scanned
 * callback => (errror, result)

> makeComment(fileHash | url, comment, [tags], callback) - Make comments on files | URLs

 * fileHash | url => md5 | sha1 | sha256 of the file or the URL itself
 * comment  => the actual comment
 * tags     => [optional] array containing the list of tags
 * callback => (errror, result)

You may add the hashtags as part of the comment itself. If you add tags to the 'tags' argument, they are automatically appended to the comment argument. You may omit the # prefix of the tags array. It is automatically added if it's missing.

makeComment(hash, 'foo', ['bar', 'baz'], [...]) is going to evaluate the comment as: 'foo #bar #baz'.

## Usage mode

```javascript
var vt = require('virustotal.js');
vt.setKey('your-api-key');
vt.scanFile({filename: 'foo.exe', size: 1024, stream: readableStreamInstance}, function (err, res) {
	if (err) {
		console.error(err);
	} else {
		console.log(res);
	}
});
```

## Error Handling

In case of coding errors, it thorws Error() instances. Otherwise, API errors are returned as the error argument of the passed callback.
