# Generating keybase.js

    node r.js -o baseUrl=. name=almond.js include=main out=keybase.js optimize=none


# Testing

    mocha test


# Using openpgp.js

**This isn't currently supported**

1. Clone openpgp.js repo
1. Remove crypto from external arrays in Gruntfile
1. Run grunt
1. Copy generated openpgp.js file here
1. Generate keybase.js
