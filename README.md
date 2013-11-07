## About

VirusTotal API 2.0 client for node.js.

## Installation

> npm install virustotal.js

## Reference



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
