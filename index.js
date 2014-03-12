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
//   credential  - The credential String. Required.
//                 Consists of Access Key ID, Date, Region, Service and termination string
//                 joined with slashes.
//
// Returns the instance.
function Signator(options) {
  if (options.secret) {
    this.secret = options.secret;
  } else if (options.derivedKey) {
    this.derivedKey = options.derivedKey;
  } else {
    throw new Error('Either secret or derivedKey is required.');
  }

  if (!options.credential) {
    throw new Error('credential is required.');
  }

  var parts = options.credential.split('/');
  if (parts.length !== 5) {
    throw new Error('Invalid credential');
  }

  this.accessKeyID = parts[0];
  this.date = parts[1];
  this.region = parts[2];
  this.service = parts[3];
  this.termination = parts[4];
};

// Public: Creates the Authorization header.
//
// algorithm   - The algorithm String.
// requestDate - The request Date.
// req         - The request Object.
//   method    - The method String.
//   url       - The URL String.
//   headers   - The header Object.
//   body      - The body String.
//
// Returns the Authorization header String.
Signator.prototype.authorization = function (algorithm, requestDate, req) {
  var params = [
    'Credential=' + this.credential(),
    'SignedHeaders=' + this.signedHeaders(req.headers),
    'Signature=' + this.signature(algorithm, requestDate, req)
  ].join(', ');
  return [algorithm, params].join(' ');
};

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
  parts.push(this.hexDigest(req.body || ''));
  return parts.join("\n");
};

Signator.prototype.stringToSign = function (algorithm, requestDate, hashedRequest) {
  var parts = [];
  var iso = this.isoDateTime(requestDate);
  if (iso.indexOf(this.date) !== 0) {
    throw new Error('Invalid requestDate: ' + iso + ' for ' + this.date);
  }
  parts.push(algorithm);
  parts.push(iso);
  parts.push(this.credentialScope());
  parts.push(hashedRequest);
  return parts.join("\n");
};

Signator.prototype.signingKey = function (requestDate) {
  var date = this.isoDate(requestDate);
  var kDate = this.hmac('AWS4' + this.secret, date);
  var kRegion = this.hmac(kDate, this.region);
  var kService = this.hmac(kRegion, this.service);
  return this.hmac(kService, this.termination);
};

Signator.prototype.credential = function () {
  return [this.accessKeyID, this.credentialScope()].join('/');
};

Signator.prototype.credentialScope = function () {
  return [this.date, this.region, this.service, this.termination].join('/');
};

Signator.prototype.getPath = function (uri) {
  var parsed = url.parse(uri);
  return parsed.path;
};

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
};

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
};

Signator.prototype.signedHeaders = function (headers) {
  return Object.keys(headers)
               .map(function (key) { return key.toLowerCase(); })
               .sort()
               .join(';');
};

Signator.prototype.hexDigest = function (str) {
  var shasum = crypto.createHash('sha256');
  shasum.update(str);
  return shasum.digest('hex');
};

Signator.prototype.hmac = function (key, data) {
  var hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest();
};

Signator.prototype.isoDate = function (date) {
  var y = date.getFullYear();
  var m = date.getMonth() + 1;
  var d = date.getDate();
  return [y, this._pad(m), this._pad(d)].join('');
}

Signator.prototype.isoDateTime = function (date) {
  var hours = date.getHours();
  var minutes = date.getMinutes();
  var seconds = date.getSeconds();

  var parts = [
    this.isoDate(date), 'T',
    this._pad(hours), this._pad(minutes), this._pad(seconds), 'Z'
  ];
  return parts.join('');
};

Signator.prototype._pad = function (num) {
  var str = num.toString();
  if (str.length < 2) {
    str = '0' + str;
  }
  return str;
};

module.exports = Signator;
