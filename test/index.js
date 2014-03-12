var Signator = require('..');
var test = require('tape');

function createSignator() {
  return new Signator({
    secret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1',
    service: 'iam',
    termination: 'aws4_request'
  });
}

test('signature secret', function (t) {
  var sig = createSignator();
  var algorithm = 'AWS4-HMAC-SHA256';
  var requestDate = '20110909T233600Z';
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

  var signature = sig.signature(algorithm, requestDate, req);
  var expected = 'ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c';
  t.equal(signature, expected);
  t.end();
});

test('signature derivedKey', function (t) {
  var sig = new Signator({
    derivedKey: '98f1d889fec4f4421adc522bab0ce1f82e6929c262ed15e5a94c90efd1e3b0e7',
    region: 'us-east-1',
    service: 'iam',
    termination: 'aws4_request'
  });
  var algorithm = 'AWS4-HMAC-SHA256';
  var requestDate = '20110909T233600Z';
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

  var signature = sig.signature(algorithm, requestDate, req);
  var expected = 'ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c';
  t.equal(signature, expected);
  t.end();
});

test('canonicalRequest with body', function (t) {
  var sig = createSignator();
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
  var sig = createSignator();
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

test('stringToSign', function (t) {
  var sig = createSignator();
  var algorithm = 'AWS4-HMAC-SHA256';
  var requestDate = '20110909T233600Z';
  var hashedRequest = '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2';
  var toSign = sig.stringToSign(algorithm, requestDate, hashedRequest);
  var expected = [
    'AWS4-HMAC-SHA256',
    '20110909T233600Z',
    '20110909/us-east-1/iam/aws4_request',
    '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2'
  ].join("\n");
  t.equal(toSign, expected);
  t.end();
});

test('signingKey', function (t) {
  var sig = createSignator();
  var requestDate = '20110909T233600Z';
  var key = sig.signingKey(requestDate);
  var expected = new Buffer([152,241,216,137,254,196,244,66,26,220,82,43,171,12,225,248,46,105,41,194,98,237,21,229,169,76,144,239,209,227,176,231]);
  t.equal(key.toString('hex'), expected.toString('hex'));
  t.end();
});

test('credentialScope', function (t) {
  var sig = createSignator();
  var scope = sig.credentialScope('20110909T233600Z');
  t.equal(scope, '20110909/us-east-1/iam/aws4_request');
  t.end();
});

test('canonicalQueryString empty', function (t) {
  var sig = createSignator();
  var url = 'http://foo.com/hello';
  var query = sig.canonicalQueryString(url);
  t.equal(query, '');
  t.end();
});

test('canonicalQueryString present', function (t) {
  var sig = createSignator();
  var url = 'http://foo.com/hello?foo=bar&abc=123';
  var query = sig.canonicalQueryString(url);
  t.equal(query, 'abc=123&foo=bar');
  t.end();
});

test('signedHeaders', function (t) {
  var sig = createSignator();
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
  var sig = createSignator();
  var date = new Date(2014, 3 - 1, 13, 12, 5, 6);
  t.plan(1);
  t.equal(sig.isoDate(date), '20140313T120506Z');
});
