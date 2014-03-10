var sig = require('..');
var test = require('tape');

test('canonicalRequest', function (t) {
  var method = 'post';
  var url = 'http://iam.amazonaws.com/';
  var headers = {
    'Host': 'iam.amazonaws.com',
    'X-AMZ-Date': '20110909T233600Z',
    'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
  };
  var payload = 'Action=ListUsers&Version=2010-05-08';
  var req = sig.canonicalRequest(method, url, headers, payload);
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
  t.equal(req, expected);
  t.end();
});

test('stringToSign', function (t) {
  var algorithm = 'AWS4-HMAC-SHA256';
  var requestDate = '20110909T233600Z';
  var scope = '20110909/us-east-1/iam/aws4_request';
  var hashedRequest = '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2';
  var toSign = sig.stringToSign(algorithm, requestDate, scope, hashedRequest);
  var expected = [
    'AWS4-HMAC-SHA256',
    '20110909T233600Z',
    '20110909/us-east-1/iam/aws4_request',
    '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2'
  ].join("\n");
  t.equal(toSign, expected);
  t.end();
});

test('canonicalQueryString empty', function (t) {
  var url = 'http://foo.com/hello';
  var query = sig.canonicalQueryString(url);
  t.equal(query, '');
  t.end();
});

test('canonicalQueryString present', function (t) {
  var url = 'http://foo.com/hello?foo=bar&abc=123';
  var query = sig.canonicalQueryString(url);
  t.equal(query, 'abc=123&foo=bar');
  t.end();
});

test('signedHeaders', function (t) {
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
