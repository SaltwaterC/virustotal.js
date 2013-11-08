## About

VirusTotal API 2.0 client for node.js.

## Installation

> npm install virustotal.js

## Reference

 * [setKey(apiKey)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#setKey) - Sets the VirusTotal API key
 * [getDomainReport(resource, callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#getDomainReport) - Retrieve a domain report
 * [getFileReport(resource, callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#getFileReport) - Retrieve a file scan report
 * [getIpReport(resource, callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#getIpReport) - Retrieve IP address report
 * [getUrlReport(resource, [scan,] callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#getUrlReport) - Retrieve an URL scan report
 * [makeComment(resource, comment, [tags,] callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#makeComment) - Creates a new comment for file/URL
 * [rescanFile(resource, callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#rescanFile) - Rescan already submitted files
 * [scanFile(resource, callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#scanFile) - Send and scan a file
 * [scanUrl(resource, callback)](http://saltwaterc.github.io/virustotal.js/module-virustotal.html#scanUrl) - Submit and scan a URL

## Usage mode

```javascript
var virustotal = require('virustotal.js');
virustotal.setKey('your-api-key');
virustotal.scanFile('file.exe', function (err, res) {
	if (err) {
		console.error(err);
		return;
	}
	
	console.log(res);
	
});
```
