/**
 * Unit test for RBAC authorization logic and role hierarchy
 */
const { ROLE_LEVELS } = require('../src/middleware/rbac');

function testRoleHierarchy() {
  console.log('Testing RBAC Role Hierarchy...');

  if (ROLE_LEVELS.Owner !== 3) throw new Error('Owner level must be 3');
  if (ROLE_LEVELS.Editor !== 2) throw new Error('Editor level must be 2');
  if (ROLE_LEVELS.Viewer !== 1) throw new Error('Viewer level must be 1');

  // Verify hierarchy checks
  const canOwnerEdit = ROLE_LEVELS.Owner >= ROLE_LEVELS.Editor;
  const canOwnerView = ROLE_LEVELS.Owner >= ROLE_LEVELS.Viewer;
  const canEditorEdit = ROLE_LEVELS.Editor >= ROLE_LEVELS.Editor;
  const canEditorDeleteScrapbook = ROLE_LEVELS.Editor >= ROLE_LEVELS.Owner;
  const canViewerEdit = ROLE_LEVELS.Viewer >= ROLE_LEVELS.Editor;
  const canViewerView = ROLE_LEVELS.Viewer >= ROLE_LEVELS.Viewer;

  if (!canOwnerEdit || !canOwnerView) throw new Error('Owner permissions hierarchy failed');
  if (!canEditorEdit || canEditorDeleteScrapbook) throw new Error('Editor permissions hierarchy failed');
  if (canViewerEdit || !canViewerView) throw new Error('Viewer permissions hierarchy failed');

  console.log('RBAC Role Hierarchy Validation Passed!');
}

testRoleHierarchy();
