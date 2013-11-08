'use strict';

/*global describe: true, it: true, before: true, after: true*/

var lib = require('../');
var assert = require('chai').assert;

lib.setKey(process.env.VIRUSTOTAL_API_KEY);

describe('REMOTE tests', function() {

	describe('REMOTE getDomainReport()', function() {
		it('should return a domain report', function(done) {
			lib.getDomainReport('example.com', function(err, res) {
				assert.ifError(err);
				assert.isNull(err);

				assert.strictEqual(res.response_code, 1);
				assert.strictEqual(res.verbose_msg, 'Domain found in dataset');

				done();
			});
		});
	});

	describe('REMOTE getFileReport()', function() {
		it('should return a file report', function(done) {
			lib.getFileReport(
				'2fc19a61b81055c199f23de35b7eb8b2827e283442965bc1898c0e044563d836',
				function(err, res) {
					assert.ifError(err);
					assert.isNull(err);

					assert.strictEqual(res.response_code, 1);
					assert.strictEqual(res.resource, '2fc19a61b81055c199f23de35b7eb8b2827e283442965bc1898c0e044563d836');

					done();
				}
			);
		});
	});

	describe('REMOTE getIpReport()', function() {
		it('should fail since it requested an invalid IP', function(done) {
			lib.getIpReport('417.216.55.69', function(err, res) {
				assert.instanceOf(err, Error);

				assert.strictEqual(err.json.response_code, 0);
				// this is odd since the service claims accepting only IPv4 addresses
				// but the above address is taken from one of the many CSI fails
				assert.strictEqual(err.json.verbose_msg, 'IP address not found in dataset');

				assert.isUndefined(res);

				done();
			});
		});
	});

	describe('REMOTE getUrlReport', function() {
		it('should return an URL report', function(done) {
			lib.getUrlReport('http://example.org/', function(err, res) {
				assert.ifError(err);
				assert.isNull(err);

				assert.strictEqual(res.response_code, 1);
				assert.strictEqual(res.url, 'http://example.org/');

				done();
			});
		});
	});

});
