var Signatory = require('..');
var test = require('tape');
var encHex = require('crypto-js/enc-hex');

function createSignatory() {
  return new Signatory({
    secret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    algorithm: 'AWS4-HMAC-SHA256',
    credential: 'AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request'
  });
}

test('constructor without secret or derived key', function (t) {
  t.plan(1);
  t.throws(function () {
    new Signatory({
      algorithm: 'AWS4-HMAC-SHA256',
      credential: 'ACCESS_KEY_ID/20110909/us-east-1/iam/aws4_request'
    });
  });
});

test('constructor without credential', function (t) {
  t.plan(1);
  t.throws(function () {
    new Signatory({
      secret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      algorithm: 'AWS4-HMAC-SHA256'
    });
  });
});

test('constructor with invalid credential', function (t) {
  t.plan(1);
  t.throws(function () {
    new Signatory({
      secret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      algorithm: 'AWS4-HMAC-SHA256',
      credential: 'Invalid Credential!!!'
    });
  });
});

test('authorization', function (t) {
  var sig = createSignatory();
  var requestDate = new Date(2011, 9 - 1, 9, 23, 36, 0);
  var req = {
    method: 'post',
    url: 'http://iam.amazonaws.com/',
    headers: {
      'Host': 'iam.amazonaws.com',
      'X-AMZ-Date': '20110909T233600Z',
      'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
    },
    body: 'Action=ListUsers&Version=2010-05-08'
  };

  var authorization = sig.authorization(requestDate, req);
  var expected = [
    'AWS4-HMAC-SHA256',
    'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request,',
    'SignedHeaders=content-type;host;x-amz-date,',
    'Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c'
  ].join(' ');
  t.equal(authorization, expected);
  t.end();
});

test('signature secret', function (t) {
  var sig = createSignatory();
  var requestDate = new Date(2011, 9 - 1, 9, 23, 36, 0);
  var req = {
    method: 'post',
    url: 'http://iam.amazonaws.com/',
    headers: {
      'Host': 'iam.amazonaws.com',
      'X-AMZ-Date': '20110909T233600Z',
      'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
    },
    body: 'Action=ListUsers&Version=2010-05-08'
  };

  var signature = sig.signature(requestDate, req);
  var expected = 'ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c';
  t.equal(signature, expected);
  t.end();
});

test('signature derivedKey', function (t) {
  var sig = new Signatory({
    derivedKey: '98f1d889fec4f4421adc522bab0ce1f82e6929c262ed15e5a94c90efd1e3b0e7',
    algorithm: 'AWS4-HMAC-SHA256',
    credential: 'ACCESS_KEY_ID/20110909/us-east-1/iam/aws4_request'
  });
  var requestDate = new Date(2011, 9 - 1, 9, 23, 36, 0);
  var req = {
    method: 'post',
    url: 'http://iam.amazonaws.com/',
    headers: {
      'Host': 'iam.amazonaws.com',
      'X-AMZ-Date': '20110909T233600Z',
      'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
    },
    body: 'Action=ListUsers&Version=2010-05-08'
  };

  var signature = sig.signature(requestDate, req);
  var expected = 'ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c';
  t.equal(signature, expected);
  t.end();
});

test('canonicalRequest with body', function (t) {
  var sig = createSignatory();
  var req = {
    method: 'post',
    url: 'http://iam.amazonaws.com/',
    headers: {
      'Host': 'iam.amazonaws.com',
      'X-AMZ-Date': '20110909T233600Z',
      'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
    },
    body: 'Action=ListUsers&Version=2010-05-08'
  };

  var canonicalReq = sig.canonicalRequest(req);
  var expected = [
    'POST',
    '/',
    '',
    'content-type:application/x-www-form-urlencoded; charset=utf-8',
    'host:iam.amazonaws.com',
    'x-amz-date:20110909T233600Z',
    '',
    'content-type;host;x-amz-date',
    'b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2'
  ].join("\n");
  t.equal(canonicalReq, expected);
  t.end();
});

test('canonicalRequest without body', function (t) {
  var sig = createSignatory();
  var req = {
    method: 'get',
    url: 'http://iam.amazonaws.com/',
    headers: {
      'Host': 'iam.amazonaws.com',
      'X-AMZ-Date': '20110909T233600Z'
    }
  };

  t.doesNotThrow(sig.canonicalRequest.bind(sig, req));
  t.end();
});

test('stringToSign with valid request date', function (t) {
  var sig = createSignatory();
  var requestDate = new Date(2011, 9 - 1, 9, 23, 36, 0);
  var hashedRequest = '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2';
  var toSign = sig.stringToSign(requestDate, hashedRequest);
  var expected = [
    'AWS4-HMAC-SHA256',
    '20110909T233600Z',
    '20110909/us-east-1/iam/aws4_request',
    '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2'
  ].join("\n");
  t.equal(toSign, expected);
  t.end();
});

test('stringToSign with invalid request date', function (t) {
  var sig = createSignatory();
  var requestDate = new Date(2013, 9 - 1, 9, 23, 36, 0);
  var hashedRequest = '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2';
  t.plan(1);
  t.throws(function () {
    sig.stringToSign(requestDate, hashedRequest);
  });
});

test('signingKey', function (t) {
  var sig = createSignatory();
  var requestDate = new Date(2011, 9 - 1, 9, 23, 36, 0);
  var key = sig.signingKey(requestDate);
  var expected = new Buffer([152,241,216,137,254,196,244,66,26,220,82,43,171,12,225,248,46,105,41,194,98,237,21,229,169,76,144,239,209,227,176,231]);
  t.equal(key.toString(encHex), expected.toString('hex'));
  t.end();
});

test('credential', function (t) {
  var sig = createSignatory();
  var credential = sig.credential();
  t.equal(credential, 'AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request');
  t.end();
});

test('credentialScope', function (t) {
  var sig = createSignatory();
  var scope = sig.credentialScope();
  t.equal(scope, '20110909/us-east-1/iam/aws4_request');
  t.end();
});

test('canonicalQueryString empty', function (t) {
  var sig = createSignatory();
  var url = 'http://foo.com/hello';
  var query = sig.canonicalQueryString(url);
  t.equal(query, '');
  t.end();
});

test('canonicalQueryString present', function (t) {
  var sig = createSignatory();
  var url = 'http://foo.com/hello?foo=bar&abc=123';
  var query = sig.canonicalQueryString(url);
  t.equal(query, 'abc=123&foo=bar');
  t.end();
});

test('signedHeaders', function (t) {
  var sig = createSignatory();
  var headers = {
    'Host': 'iam.amazonaws.com',
    'X-AMZ-Date': '20110909T233600Z',
    'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
  };
  var signed = sig.signedHeaders(headers);
  var expected = 'content-type;host;x-amz-date';
  t.equal(signed, expected);
  t.end();
});

test('isoDate', function (t) {
  var sig = createSignatory();
  var date = new Date(2014, 3 - 1, 13, 12, 5, 6);
  t.plan(1);
  t.equal(sig.isoDate(date), '20140313');
});

test('isoDateTime', function (t) {
  var sig = createSignatory();
  var date = new Date(2014, 3 - 1, 13, 12, 5, 6);
  t.plan(1);
  t.equal(sig.isoDateTime(date), '20140313T120506Z');
});
