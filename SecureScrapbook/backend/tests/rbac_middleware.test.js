/**
 * Detailed unit & integration test for the RBAC authorization middleware
 */
const { requireScrapbookRole } = require('../src/middleware/rbac');
const db = require('../src/db');

async function testRbacMiddleware() {
  console.log('\n--- Running RBAC Middleware Authorization Tests ---');

  // Test Case 1: Unauthenticated user (missing req.user)
  {
    const req = {
      headers: { 'x-forwarded-for': '192.168.1.50' },
      socket: { remoteAddress: '192.168.1.50' },
      params: { scrapbookId: 'sb-123' },
      method: 'GET',
      originalUrl: '/api/scrapbooks/sb-123'
    };
    let statusCode = null;
    let jsonResponse = null;
    const res = {
      status: (code) => { statusCode = code; return res; },
      json: (data) => { jsonResponse = data; return res; }
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };

    const middleware = requireScrapbookRole('Viewer');
    await middleware(req, res, next);

    if (statusCode !== 401 || nextCalled) {
      throw new Error(`Test 1 Failed: Expected 401, got ${statusCode}`);
    }
    console.log('✓ Test 1 Passed: Unauthenticated request blocked with 401 Unauthorized.');
  }

  // Test Case 2: Viewer attempting Editor action (Blocked with 403)
  {
    // Mock db.query for this test case
    const originalQuery = db.query;
    db.query = async (sql, params) => {
      if (sql.includes('FROM scrapbooks')) {
        return { rows: [{ id: 'sb-123', owner_id: 'user-owner-999', is_archived: false }] };
      }
      if (sql.includes('FROM scrapbook_permissions')) {
        return { rows: [{ role: 'Viewer', granted_by: 'user-owner-999' }] };
      }
      return { rows: [] };
    };

    const req = {
      user: { id: 'user-alice-111', email: 'alice@example.com' },
      headers: { 'x-forwarded-for': '192.168.1.50' },
      socket: { remoteAddress: '192.168.1.50' },
      params: { scrapbookId: 'sb-123' },
      method: 'POST',
      originalUrl: '/api/scrapbooks/sb-123/pages'
    };
    let statusCode = null;
    let jsonResponse = null;
    const res = {
      status: (code) => { statusCode = code; return res; },
      json: (data) => { jsonResponse = data; return res; }
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };

    const middleware = requireScrapbookRole('Editor');
    await middleware(req, res, next);

    if (statusCode !== 403 || nextCalled) {
      throw new Error(`Test 2 Failed: Expected 403 Forbidden, got ${statusCode}`);
    }
    console.log(`✓ Test 2 Passed: Viewer blocked with 403 Forbidden when accessing Editor route: ${jsonResponse.message}`);

    db.query = originalQuery;
  }

  // Test Case 3: Editor accessing Editor action (Allowed)
  {
    const originalQuery = db.query;
    db.query = async (sql, params) => {
      if (sql.includes('FROM scrapbooks')) {
        return { rows: [{ id: 'sb-123', owner_id: 'user-owner-999', is_archived: false }] };
      }
      if (sql.includes('FROM scrapbook_permissions')) {
        return { rows: [{ role: 'Editor', granted_by: 'user-owner-999' }] };
      }
      return { rows: [] };
    };

    const req = {
      user: { id: 'user-bob-222', email: 'bob@example.com' },
      headers: {},
      socket: { remoteAddress: '127.0.0.1' },
      params: { scrapbookId: 'sb-123' },
      method: 'POST',
      originalUrl: '/api/scrapbooks/sb-123/pages'
    };
    let statusCode = null;
    const res = {
      status: (code) => { statusCode = code; return res; },
      json: (data) => res
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };

    const middleware = requireScrapbookRole('Editor');
    await middleware(req, res, next);

    if (!nextCalled || req.scrapbookPermission.role !== 'Editor') {
      throw new Error('Test 3 Failed: Editor should be permitted to call next()');
    }
    console.log('✓ Test 3 Passed: Editor granted access to modify pages.');

    db.query = originalQuery;
  }

  // Test Case 4: Primary Owner accessing Owner-only route (Allowed via ownership)
  {
    const originalQuery = db.query;
    db.query = async (sql, params) => {
      if (sql.includes('FROM scrapbooks')) {
        return { rows: [{ id: 'sb-123', owner_id: 'user-owner-999', is_archived: false }] };
      }
      return { rows: [] };
    };

    const req = {
      user: { id: 'user-owner-999', email: 'owner@example.com' },
      headers: {},
      socket: { remoteAddress: '127.0.0.1' },
      params: { scrapbookId: 'sb-123' },
      method: 'DELETE',
      originalUrl: '/api/scrapbooks/sb-123'
    };
    const res = {
      status: (code) => res,
      json: (data) => res
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };

    const middleware = requireScrapbookRole('Owner');
    await middleware(req, res, next);

    if (!nextCalled || req.scrapbookPermission.role !== 'Owner' || !req.scrapbookPermission.isPrimaryOwner) {
      throw new Error('Test 4 Failed: Owner was not recognized');
    }
    console.log('✓ Test 4 Passed: Owner recognized via primary ownership and permitted.');

    db.query = originalQuery;
  }

  console.log('All RBAC Middleware Verification Tests Passed Successfully!\n');
}

testRbacMiddleware().catch(err => {
  console.error('RBAC Test Error:', err);
  process.exit(1);
});
