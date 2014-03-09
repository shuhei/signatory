var signature = require('..');
var test = require('tape');

test('foo bar', function (t) {
  t.plan(2);
  t.equal(1 + 1, 2);
  t.ok(true);
});

test('canonicalRequest', function (t) {
  var method = 'post';
  var url = 'http://iam.amazonaws.com/';
  var headers = {
    'Host': 'iam.amazonaws.com',
    'X-AMZ-Date': '20110909T233600Z',
    'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
  };
  var payload = 'Action=ListUsers&Version=2010-05-08';
  var req = signature.canonicalRequest(method, url, headers, payload);
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

test('canonicalQueryString empty', function (t) {
  var url = 'http://foo.com/hello';
  var query = signature.canonicalQueryString(url);
  t.equal(query, '');
  t.end();
});

test('canonicalQueryString present', function (t) {
  var url = 'http://foo.com/hello?foo=bar&abc=123';
  var query = signature.canonicalQueryString(url);
  t.equal(query, 'abc=123&foo=bar');
  t.end();
});

test('signedHeaders', function (t) {
  var headers = {
    'Host': 'iam.amazonaws.com',
    'X-AMZ-Date': '20110909T233600Z',
    'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'
  };
  var signed = signature.signedHeaders(headers);
  var expected = 'content-type;host;x-amz-date';
  t.equal(signed, expected);
  t.end();
});
