/**
 * SAS introspection & (Part B) signing (slice 9). Standalone plain TS, no
 * Angular. `parseSasUrl` is the consolidated typed reader built on the existing
 * azure-blob primitives; `describeExpiry` turns a parsed expiry into the badge/
 * copy vocabulary shared by the wizard, connections list, and browse header.
 */
export { parseSasUrl, type ParsedSas, type SasKind } from './parse-sas-url';
export {
  describeExpiry,
  WARNING_WINDOW_DAYS,
  IMMINENT_WINDOW_DAYS,
  type ExpiryStatus,
  type ExpiryTone,
} from './expiry-status';
export {
  signServiceSasToken,
  SIGNED_SAS_VERSION,
  type ServiceSasInput,
  type SasIpRange,
} from './sign-service-sas';
export {
  mintContainerBrowseSas,
  mintBlobReadSasUrl,
  mintContainerManageSas,
  mintContainerUploadSas,
  manageSasProvider,
  uploadSasProvider,
  BROWSE_SAS_TTL_MS,
  DELETE_SAS_PERMISSIONS,
  MANAGE_SAS_REMINT_MARGIN_MS,
  MANAGE_SAS_TTL_MS,
  RENAME_SAS_PERMISSIONS,
  TIER_SAS_PERMISSIONS,
  type ManageSasPermissions,
  UPLOAD_SAS_TTL_MS,
  UPLOAD_SAS_REMINT_MARGIN_MS,
} from './mint-sas';
