'use strict';

/*global describe: true, it: true, before: true, after: true*/

var lib = require('../');
var assert = require('chai').assert;

describe('LOCAL tests', function() {

	var testExceptions = function(method) {
		describe('LOCAL ' + method + ' exceptions', function() {
			it('should throw errors regarding the missing arguments', function(done) {
				var throws1 = function() {
					lib[method]();
				};

				var throws2 = function() {
					lib[method]('resource');
				};

				assert.throws(throws1, Error, 'You need to define a resource argument in order to use ' + method + '().');
				assert.throws(throws2, Error, 'You need to define a callback for ' + method + '().');

				done();
			});
		});
	};

	testExceptions('scanFile');
	testExceptions('rescanFile');
	testExceptions('getFileReport');
	testExceptions('scanUrl');
	testExceptions('getUrlReport');
	testExceptions('getIpReport');
	testExceptions('getDomainReport');
	testExceptions('makeComment');
});
