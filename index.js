var url = require('url');
var qs = require('querystring');
var crypto = require('crypto');

// http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

// Public: Sign requests with the given secret key.
//
// options       - The configuration Object.
//   secret      - The secret access key String. One of this and derivedKey is required.
//   derivedKey  - The derived signing key String in hex. One of this and secret is required.
//                 If this is set, it should have been created with the same region,
//                 service and termination as the options.
//   region      - The region String. Required.
//   service     - The service String. Required.
//   termination - The termination String. Required.
//
// Returns the instance.
function Signator(options) {
  this.secret = options.secret;
  this.derivedKey = options.derivedKey;

  this.region = options.region;
  this.service = options.service;
  this.termination = options.termination;
}

// Public: Sign the given request.
//
// algorithm   - The algorithm String.
// requestDate - The request date String in the format of `20110909T233600Z`.
// req         - The request Object.
//   method    - The method String.
//   url       - The URL String.
//   headers   - The header Object.
//   body      - The body String.
//
// Return the signature String.
Signator.prototype.signature = function (algorithm, requestDate, req) {
  var canonicalReq = this.canonicalRequest(req);
  var hashedReq = this.hexDigest(canonicalReq);
  var toSign = this.stringToSign(algorithm, requestDate, hashedReq);
  var key;
  if (this.derivedKey) {
    key = new Buffer(this.derivedKey, 'hex');
  } else {
    key = this.signingKey(requestDate);
  }
  return this.hmac(key, toSign).toString('hex');
};

Signator.prototype.canonicalRequest = function (req) {
  var parts = [];
  parts.push(req.method.toUpperCase());
  parts.push(this.getPath(req.url));
  parts.push(this.canonicalQueryString(req.url));
  parts.push(this.canonicalHeaders(req.headers));
  parts.push(this.signedHeaders(req.headers));
  parts.push(this.hexDigest(req.body));
  return parts.join("\n");
}

Signator.prototype.stringToSign = function (algorithm, requestDate, hashedRequest) {
  var parts = [];
  parts.push(algorithm);
  parts.push(requestDate);
  parts.push(this.credentialScope(requestDate));
  parts.push(hashedRequest);
  return parts.join("\n");
}

Signator.prototype.signingKey = function (requestDate) {
  var date = requestDate.split('T')[0];
  var kDate = this.hmac('AWS4' + this.secret, date);
  var kRegion = this.hmac(kDate, this.region);
  var kService = this.hmac(kRegion, this.service);
  return this.hmac(kService, this.termination);
}

Signator.prototype.credentialScope = function (requestDate) {
  var date = requestDate.split('T')[0];
  return [date, this.region, this.service, this.termination].join("/");
};

Signator.prototype.getPath = function (uri) {
  var parsed = url.parse(uri);
  return parsed.path;
}

Signator.prototype.canonicalQueryString = function (uri) {
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

Signator.prototype.canonicalHeaders = function (headers) {
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

Signator.prototype.signedHeaders = function (headers) {
  return Object.keys(headers)
               .map(function (key) { return key.toLowerCase(); })
               .sort()
               .join(';');
}

Signator.prototype.hexDigest = function (str) {
  var shasum = crypto.createHash('sha256');
  shasum.update(str);
  return shasum.digest('hex');
}

Signator.prototype.hmac = function (key, data) {
  var hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest();
}

module.exports = Signator;
