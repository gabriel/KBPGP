# Generating keybase.js

In build:

    node r.js -o baseUrl=. name=almond.js include=main out=../keybase.js optimize=none


# Testing

    mocha test
    mocha test -g "should encrypt"


# Using openpgp.js

1. Clone `openpgp.js` repo
1. Remove crypto from external arrays in Gruntfile
1. Run grunt
1. Copy generated `openpgp.js` to the build dir


To use `openpgp.js` as the backend, change `main.js` to require openpgp instance of kbpgp.


