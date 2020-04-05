var assert = require('assert');
// var request = require('supertest')('localhost/echo3.fcgi');
var request = require('supertest')('localhost/app.fcgi');

describe('POST /test', function() {
  it('responds with status 200', function(done) {
    request.post('/test')
      .send({a:1})
      .expect(200)
      .expect('Content-Type', /json/)
      .end(function(err, resp) {
        console.log(resp.body)
        done();
      })

  });
});

describe('GET /', function() {
  it('responds with status 200', function(done) {
    request.get('/')
      .expect(200)
      .expect('Content-Type', /json/)
      .end(function(err, resp) {
        console.log(resp.body)
        done();
      });
  });
});

