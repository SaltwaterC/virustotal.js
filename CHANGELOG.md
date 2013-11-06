## v0.3
 * Library rewrite to use [http-request](https://github.com/SaltwaterC/http-request) as the HTTP layer.
 * Added the new methods from VT Public API v2.0: rescanFile(), getIpReport(), getDomainReport().
 * Removed the deprecation of passing file paths to scanFile(). The [form-data](https://github.com/felixge/node-form-data) library takes care of the multipart/form-data requests, which is way more flexible.
 * Removed the deprecated methods makeFileComment() and makeUrlComment().
 * Unit testing.
 * Documentation generated with JSDoc 3.

## v0.2.3
 * jslint compliant.
 * Deprecated the possibility to pass file paths to the scanFile() method.

## v0.2.2
 * Avoids a possible race condition for scanFile() when a Read Stream error event is emitted.

## v0.2.1
 * Added the possibility to pass a stream to scanFile().

## v0.2
 * Updates the client to use the new VT Public API, v2.0. The client API remains backward compatible.
 * New method: makeComment().
 * Deprecated the use of makeFileComment() and makeUrlComment().

## v0.1
 * Initial release, featuring support for VirusTotal Public API 1.0.
