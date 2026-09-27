export { createLogger, MSG, TENANCY_LOGGER, type TenancyLogger } from './logging.js';

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

export {
  assurerRole,
  assertSafePassword,
  type RoleCredentials,
  type RoleVoulu,
  type OptionsRoles,
} from './migrations/001-roles.js';

export {
  auditRls,
  assertRlsIsSound,
  TABLES_PUBLIQUES_SOCLE,
  type RlsAudit,
  type OptionsAuditRls,
} from './rls/guards.js';

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

export {
  buildAbility,
  actionCasl,
  loadAbilityContext,
  assertCan,
  ForbiddenError,
  type AppAbility,
  type AbilityContext,
} from './authorization/ability.js';
