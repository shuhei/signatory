var url = require('url');
var qs = require('querystring');
var crypto = require('crypto');

// http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

function Signator(secret, region, service, termination) {
  this.secret = secret;
  this.region = region;
  this.service = service;
  this.termination = termination;
}

Signator.prototype.sign = function (algorithm, requestDate, method, url, headers, payload) {
  var req = this.canonicalRequest(method, url, headers, payload);
  var hashedReq = this.hexDigest(req);
  var toSign = this.stringToSign(algorithm, requestDate, hashedReq);
  var key = this.signingKey(requestDate);
  return this.hmac(key, toSign).toString('hex');
};

Signator.prototype.canonicalRequest = function (method, uri, headers, payload) {
  var parts = [];
  parts.push(method.toUpperCase());
  parts.push(this.getPath(uri));
  parts.push(this.canonicalQueryString(uri));
  parts.push(this.canonicalHeaders(headers));
  parts.push(this.signedHeaders(headers));
  parts.push(this.hexDigest(payload));
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
