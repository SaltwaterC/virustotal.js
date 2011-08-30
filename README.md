## About

VirusTotal API client for node.js. Currently under development and barely usable.

## Stuff that works

```javascript
var vt = require('virustotal.js'); // need to be in node_modules to work like this
vt.setKey('your-api-key');

vt.getFileReport({resource: 'resource-hash'}, function (err, res) {
	if (err) {
		console.error(err);
	} else {
		console.log(res);
	}
});

vt.scanFile({file: '/path/to/foo.bar'}, function (err, res) {
	if (err) {
		console.error(err);
	} else {
		console.log(res);
	}
});
```

All the methods accept a couple of arguments:

 * arg - an object containing the VirusTotal API information.
 * callback - which is executed when the processing ends. The callback follows the node.js convention: (error, result).
