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
//   algorithm   - The algorithm String.
//   credential  - The credential String. Required.
//                 Consists of Access Key ID, Date, Region, Service and termination string
//                 joined with slashes.
//
// Returns the instance.
function Signatory(options) {
  if (options.secret) {
    this.secret = options.secret;
  } else if (options.derivedKey) {
    this.derivedKey = options.derivedKey;
  } else {
    throw new Error('Either secret or derivedKey is required.');
  }

  if (!options.algorithm) {
    throw new Error('algorithm is required.');
  }
  this.algorithm = options.algorithm;
  var algoParts = options.algorithm.split('-');
  this.hasher = algoParts[algoParts.length - 1].toLowerCase();
  if (['sha256', 'sha512'].indexOf(this.hasher) < 0) {
    throw new Error('Invalid algorithm: ' + options.algorithm);
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
// requestDate - The request Date.
// req         - The request Object.
//   method    - The method String.
//   url       - The URL String.
//   headers   - The header Object.
//   body      - The body String.
//
// Returns the Authorization header String.
Signatory.prototype.authorization = function (requestDate, req) {
  var params = [
    'Credential=' + this.credential(),
    'SignedHeaders=' + this.signedHeaders(req.headers),
    'Signature=' + this.signature(requestDate, req)
  ].join(', ');
  return [this.algorithm, params].join(' ');
};

Signatory.prototype.signature = function (requestDate, req) {
  var canonicalReq = this.canonicalRequest(req);
  var hashedReq = this.hexDigest(canonicalReq);
  var toSign = this.stringToSign(requestDate, hashedReq);
  var key;
  if (this.derivedKey) {
    key = new Buffer(this.derivedKey, 'hex');
  } else {
    key = this.signingKey(requestDate);
  }
  return this.hmac(key, toSign).toString('hex');
};

Signatory.prototype.canonicalRequest = function (req) {
  var parts = [];
  parts.push(req.method.toUpperCase());
  parts.push(this.getPath(req.url));
  parts.push(this.canonicalQueryString(req.url));
  parts.push(this.canonicalHeaders(req.headers));
  parts.push(this.signedHeaders(req.headers));
  parts.push(this.hexDigest(req.body || ''));
  return parts.join("\n");
};

Signatory.prototype.stringToSign = function (requestDate, hashedRequest) {
  var parts = [];
  var iso = this.isoDateTime(requestDate);
  if (iso.indexOf(this.date) !== 0) {
    throw new Error('Invalid requestDate: ' + iso + ' for ' + this.date);
  }
  parts.push(this.algorithm);
  parts.push(iso);
  parts.push(this.credentialScope());
  parts.push(hashedRequest);
  return parts.join("\n");
};

Signatory.prototype.signingKey = function (requestDate) {
  var date = this.isoDate(requestDate);
  var kDate = this.hmac('AWS4' + this.secret, date);
  var kRegion = this.hmac(kDate, this.region);
  var kService = this.hmac(kRegion, this.service);
  return this.hmac(kService, this.termination);
};

Signatory.prototype.credential = function () {
  return [this.accessKeyID, this.credentialScope()].join('/');
};

Signatory.prototype.credentialScope = function () {
  return [this.date, this.region, this.service, this.termination].join('/');
};

Signatory.prototype.getPath = function (uri) {
  var parsed = url.parse(uri);
  return parsed.path;
};

Signatory.prototype.canonicalQueryString = function (uri) {
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

Signatory.prototype.canonicalHeaders = function (headers) {
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

Signatory.prototype.signedHeaders = function (headers) {
  return Object.keys(headers)
               .map(function (key) { return key.toLowerCase(); })
               .sort()
               .join(';');
};

Signatory.prototype.hexDigest = function (str) {
  var shasum = crypto.createHash(this.hasher);
  shasum.update(str);
  return shasum.digest('hex');
};

Signatory.prototype.hmac = function (key, data) {
  var hmac = crypto.createHmac(this.hasher, key);
  hmac.update(data);
  return hmac.digest();
};

Signatory.prototype.isoDate = function (date) {
  var y = date.getFullYear();
  var m = date.getMonth() + 1;
  var d = date.getDate();
  return [y, this._pad(m), this._pad(d)].join('');
}

Signatory.prototype.isoDateTime = function (date) {
  var hours = date.getHours();
  var minutes = date.getMinutes();
  var seconds = date.getSeconds();

  var parts = [
    this.isoDate(date), 'T',
    this._pad(hours), this._pad(minutes), this._pad(seconds), 'Z'
  ];
  return parts.join('');
};

Signatory.prototype._pad = function (num) {
  var str = num.toString();
  if (str.length < 2) {
    str = '0' + str;
  }
  return str;
};

module.exports = Signatory;
