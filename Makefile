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
