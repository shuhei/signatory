var url = require('url');
var qs = require('querystring');
var crypto = require('crypto');

// http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

function canonicalRequest(method, uri, headers, payload) {
  var parts = [];
  parts.push(method.toUpperCase());
  parts.push(getPath(uri));
  parts.push(canonicalQueryString(uri));
  parts.push(canonicalHeaders(headers));
  parts.push(signedHeaders(headers));
  parts.push(hexDigest(payload));
  return parts.join("\n");
}

function stringToSign(algorithm, requestDate, scope, hashedRequest) {
  var parts = [];
  parts.push(algorithm);
  parts.push(requestDate);
  parts.push(scope);
  parts.push(hashedRequest);
  return parts.join("\n");
}

function getPath(uri) {
  var parsed = url.parse(uri);
  return parsed.path;
}

function canonicalQueryString(uri) {
  var parsed = url.parse(uri);
  if (!parsed.query) {
    return '';
  }
  var params = qs.parse(parsed.query);
  var sortedKeys = Object.keys(params).sort();
  var sortedParams = sortedKeys.map(function (key) {
    return key + '=' + params[key];
  });
  return sortedParams.join('&');
}

function canonicalHeaders(headers) {
  var keyValues = Object.keys(headers).map(function (key) {
    return [key.toLowerCase(), headers[key]];
  });
  keyValues.sort(function (left, right) {
    return left[0].localeCompare(right[0]);
  });
  return keyValues.map(function (item) {
    return item[0] + ':' + item[1] + "\n";
  }).join('');
}

function signedHeaders(headers) {
  return Object.keys(headers)
               .map(function (key) { return key.toLowerCase(); })
               .sort()
               .join(';');
}

function hexDigest(str) {
  var shasum = crypto.createHash('sha256');
  shasum.update(str);
  return shasum.digest('hex');
}

module.exports = {
  canonicalRequest: canonicalRequest,
  stringToSign: stringToSign,
  canonicalQueryString: canonicalQueryString,
  signedHeaders: signedHeaders
};
