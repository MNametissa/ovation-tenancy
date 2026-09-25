export {
  createLogger,
  MSG,
  TENANCY_LOGGER,
  type TenancyLogger,
} from './logging.js';

export {
  withRlsDisabled,
  assertForceEnabled,
  assertPoliciesPresent,
  assertRoleIsSafe,
  type RlsGuardOptions,
} from './migrations/rls-guard.js';

export {
  runMigrations,
  rollbackMigrations,
  MIGRATIONS,
  type Migration,
  type RunOptions,
  type MigrationResult,
} from './migrations/runner.js';

export type { RoleCredentials } from './migrations/001-roles.js';

export { auditRls, assertRlsIsSound, type RlsAudit } from './rls/guards.js';

export {
  TenantContext,
  CLS_TENANT,
  CLS_USER,
  type TenantScope,
} from './context/tenant-context.js';

export {
  RoleService,
  SYSTEM_ROLES,
  type Role,
  type RoleInput,
} from './roles/role-service.js';

export {
  PermissionSink,
  type DiscoveredPermission,
  type DiscoveredCatalog,
  type SyncReport,
} from './permissions/permission-sink.js';

export {
  AuditService,
  type AuditEntry,
  type ChainVerification,
} from './audit/audit-service.js';
