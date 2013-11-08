.PHONY: all
.DEFAULT: all
REPORTER ?= dot

all:
	@/usr/bin/env npm install

publish: all
	@/usr/bin/env npm publish

lint: all
	@tools/lint.sh

beautify:
	@tools/beautify.sh

clean:
	rm -rf node_modules

tests: test
check: test
test: all lint
	@./node_modules/.bin/mocha --reporter $(REPORTER) -g LOCAL

fulltest: all
	@./node_modules/.bin/mocha --reporter $(REPORTER)

doc:
	jsdoc --destination ../docs lib README.md

docpublish: doc
	cd ../docs && git commit --all --message "Auto generated documentation" && git push origin gh-pages
