/**
 * Permission Registry & Role Matrix — منصة عقار 2.0 (Section 3.2, 3.3, 5.2)
 * Single source of truth for RBAC permission keys and Separation of Duties (SoD).
 */

export const PERMISSIONS = Object.freeze({
  // Properties (Section 3.3)
  PROPERTIES_VIEW: 'properties.view',
  PROPERTIES_CREATE: 'properties.create',
  PROPERTIES_UPDATE_OWN: 'properties.update.own',
  PROPERTIES_UPDATE_ANY: 'properties.update.any',
  PROPERTIES_PUBLISH: 'properties.publish',
  PROPERTIES_ARCHIVE: 'properties.archive',
  PROPERTIES_VERIFY: 'properties.verify',

  // Contacts / CRM (Section 3.3)
  CONTACTS_VIEW: 'contacts.view',
  CONTACTS_CREATE: 'contacts.create',
  CONTACTS_UPDATE: 'contacts.update',
  CONTACTS_EXPORT: 'contacts.export',

  // Viewings (Section 3.3 & 5.2)
  VIEWINGS_VIEW: 'viewings.view',
  VIEWINGS_CREATE: 'viewings.create',
  VIEWINGS_CONFIRM: 'viewings.confirm',
  VIEWINGS_RESCHEDULE: 'viewings.reschedule',
  VIEWINGS_CANCEL: 'viewings.cancel',
  VIEWINGS_RECORD_OUTCOME: 'viewings.record_outcome',

  // Tasks (Section 3.3)
  TASKS_VIEW_TEAM: 'tasks.view.team',
  TASKS_ASSIGN: 'tasks.assign',
  TASKS_COMPLETE: 'tasks.complete',

  // Deals (Section 3.3)
  DEALS_CREATE: 'deals.create',
  DEALS_UPDATE: 'deals.update',
  DEALS_CLOSE: 'deals.close',
  DEALS_COMMISSION_MANAGE: 'deals.commission.manage',

  // Finance (Section 3.3)
  FINANCE_INVOICES_VIEW: 'finance.invoices.view',
  FINANCE_INVOICES_CREATE: 'finance.invoices.create',
  FINANCE_PAYMENTS_RECORD: 'finance.payments.record',
  FINANCE_PAYMENTS_CONFIRM: 'finance.payments.confirm',
  FINANCE_REFUNDS_APPROVE: 'finance.refunds.approve',
  FINANCE_LEDGER_VIEW: 'finance.ledger.view',
  FINANCE_LEDGER_POST: 'finance.ledger.post',
  FINANCE_STATEMENTS_EXPORT: 'finance.statements.export',

  // Reports, Users, Roles, Audit & Settings (Section 3.3)
  REPORTS_VIEW: 'reports.view',
  REPORTS_EXPORT: 'reports.export',
  USERS_INVITE: 'users.invite',
  USERS_SUSPEND: 'users.suspend',
  ROLES_MANAGE: 'roles.manage',
  AUDIT_LOGS_VIEW: 'audit_logs.view',
  ORG_SETTINGS_MANAGE: 'organization.settings.manage',
});

export const ALL_PERMISSION_KEYS = Object.freeze(Object.values(PERMISSIONS));
export const PERMISSION_SET = new Set(ALL_PERMISSION_KEYS);

export const SYSTEM_ROLES = Object.freeze({
  OWNER: 'owner',
  MANAGER: 'manager',
  AGENT: 'agent',
  VIEWER: 'viewer',
  ACCOUNTANT: 'accountant',
  VERIFICATION_OFFICER: 'verification_officer',
  PLATFORM_ADMIN: 'platform_admin',
});

/** Roles that MUST have MFA enabled per Section 3.10 */
export const MFA_REQUIRED_ROLES = new Set([
  SYSTEM_ROLES.OWNER,
  SYSTEM_ROLES.MANAGER,
  SYSTEM_ROLES.PLATFORM_ADMIN,
]);

/** Default role-to-permission matrix per Section 3.2 */
export const ROLE_PERMISSION_MATRIX = Object.freeze({
  [SYSTEM_ROLES.OWNER]: new Set(ALL_PERMISSION_KEYS),

  [SYSTEM_ROLES.MANAGER]: new Set([
    PERMISSIONS.PROPERTIES_VIEW,
    PERMISSIONS.PROPERTIES_CREATE,
    PERMISSIONS.PROPERTIES_UPDATE_OWN,
    PERMISSIONS.PROPERTIES_UPDATE_ANY,
    PERMISSIONS.PROPERTIES_PUBLISH,
    PERMISSIONS.PROPERTIES_ARCHIVE,
    PERMISSIONS.CONTACTS_VIEW,
    PERMISSIONS.CONTACTS_CREATE,
    PERMISSIONS.CONTACTS_UPDATE,
    PERMISSIONS.CONTACTS_EXPORT,
    PERMISSIONS.VIEWINGS_VIEW,
    PERMISSIONS.VIEWINGS_CREATE,
    PERMISSIONS.VIEWINGS_CONFIRM,
    PERMISSIONS.VIEWINGS_RESCHEDULE,
    PERMISSIONS.VIEWINGS_CANCEL,
    PERMISSIONS.VIEWINGS_RECORD_OUTCOME,
    PERMISSIONS.TASKS_VIEW_TEAM,
    PERMISSIONS.TASKS_ASSIGN,
    PERMISSIONS.TASKS_COMPLETE,
    PERMISSIONS.DEALS_CREATE,
    PERMISSIONS.DEALS_UPDATE,
    PERMISSIONS.DEALS_CLOSE,
    PERMISSIONS.REPORTS_VIEW,
    PERMISSIONS.USERS_INVITE,
    // Manager does NOT automatically get Owner-level org settings, roles.manage, or finance.refunds.approve
  ]),

  [SYSTEM_ROLES.AGENT]: new Set([
    PERMISSIONS.PROPERTIES_VIEW,
    PERMISSIONS.PROPERTIES_CREATE,
    PERMISSIONS.PROPERTIES_UPDATE_OWN,
    PERMISSIONS.CONTACTS_VIEW,
    PERMISSIONS.CONTACTS_CREATE,
    PERMISSIONS.CONTACTS_UPDATE,
    PERMISSIONS.VIEWINGS_VIEW,
    PERMISSIONS.VIEWINGS_CREATE,
    PERMISSIONS.VIEWINGS_RESCHEDULE,
    PERMISSIONS.VIEWINGS_RECORD_OUTCOME,
    PERMISSIONS.TASKS_COMPLETE,
    PERMISSIONS.DEALS_CREATE,
    PERMISSIONS.DEALS_UPDATE,
  ]),

  [SYSTEM_ROLES.VIEWER]: new Set([
    PERMISSIONS.PROPERTIES_VIEW,
    PERMISSIONS.CONTACTS_VIEW,
    PERMISSIONS.VIEWINGS_VIEW,
    PERMISSIONS.REPORTS_VIEW,
  ]),

  [SYSTEM_ROLES.ACCOUNTANT]: new Set([
    PERMISSIONS.FINANCE_INVOICES_VIEW,
    PERMISSIONS.FINANCE_INVOICES_CREATE,
    PERMISSIONS.FINANCE_PAYMENTS_RECORD,
    PERMISSIONS.FINANCE_PAYMENTS_CONFIRM,
    PERMISSIONS.FINANCE_LEDGER_VIEW,
    PERMISSIONS.FINANCE_LEDGER_POST,
    PERMISSIONS.FINANCE_STATEMENTS_EXPORT,
    PERMISSIONS.REPORTS_VIEW,
    PERMISSIONS.REPORTS_EXPORT,
  ]),

  [SYSTEM_ROLES.VERIFICATION_OFFICER]: new Set([
    PERMISSIONS.PROPERTIES_VIEW,
    PERMISSIONS.PROPERTIES_VERIFY,
    // Strictly no financial approval permissions per Section 3.2
  ]),

  [SYSTEM_ROLES.PLATFORM_ADMIN]: new Set([
    PERMISSIONS.AUDIT_LOGS_VIEW,
    PERMISSIONS.REPORTS_VIEW,
  ]),
});

/**
 * Separation of Duties (SoD) rules per Section 3.2 & 7.4:
 * Prevents the same user from both creating and approving/confirming sensitive financial operations.
 */
export const SOD_RESTRICTED_PERMISSIONS = new Set([
  PERMISSIONS.FINANCE_PAYMENTS_CONFIRM,
  PERMISSIONS.FINANCE_REFUNDS_APPROVE,
]);
