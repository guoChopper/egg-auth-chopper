'use strict';

const mock = require('egg-mock');

describe('test/auth-chopper.test.js', () => {
  let app;
  before(() => {
    app = mock.app({
      baseDir: 'apps/auth-chopper-test',
    });
    return app.ready();
  });

  after(() => app.close());
  afterEach(mock.restore);

  it('should GET /', () => {
    return app.httpRequest()
      .get('/')
      .expect('hi, authChopper')
      .expect(200);
  });
});
