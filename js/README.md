# Generating keybase.js

In build:

    node r.js -o baseUrl=. name=almond.js include=main out=../keybase.js optimize=none


# Testing

    mocha test
    mocha test -g "should encrypt"

Use jshint to make sure there aren't any syntax errors.

