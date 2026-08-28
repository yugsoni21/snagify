import { ElectronAPI } from '@electron-toolkit/preload'

// ---------------------------------------------------------------------------
// Folder stats
// ---------------------------------------------------------------------------

export interface TreeNode {
  name: string
  type: 'file' | 'dir'
  children?: TreeNode[]
}

export interface FolderStats {
  fileCount: number
  totalSizeMB: number
  languages: string[]
  filePaths: string[]
  tree: TreeNode[]
}

// ---------------------------------------------------------------------------
// Scan types
// ---------------------------------------------------------------------------

export type ScanStep =
  | 'init'
  | 'semgrep'
  | 'semgrep-skip'
  | 'semgrep-error'
  | 'gitleaks'
  | 'gitleaks-skip'
  | 'gitleaks-error'
  | 'osv'
  | 'osv-skip'
  | 'osv-error'
  | 'scaling'
  | 'scaling-skip'
  | 'scaling-error'
  | 'ai'
  | 'ai-skip'
  | 'ai-error'
  | 'done'
  | 'cancelled'

export interface ScanProgress {
  step: ScanStep
  message: string
}

export interface SemgrepFinding {
  check_id: string
  path: string
  start: { line: number; col: number }
  end: { line: number; col: number }
  extra: {
    message: string
    severity: string
    lines?: string
    metadata?: {
      category?: string
      confidence?: string
      cwe?: string[]
      owasp?: string[]
      [key: string]: unknown
    }
  }
}

export interface GitleaksFinding {
  Description: string
  StartLine: number
  EndLine: number
  Match: string
  Secret: string
  File: string
  Commit: string
  Entropy: number
  Author: string
  Date: string
  Message: string
  Tags: string[]
  RuleID: string
  Fingerprint: string
}

// ---------------------------------------------------------------------------
// AI analysis types
// ---------------------------------------------------------------------------

export interface AIFinding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  explanation: string
  fixSuggestion: string
  file: string
  line: number | null
  cwe?: string[]
  owasp?: string[]
}

export interface ComplianceIssue {
  regulation: string
  article: string
  description: string
  recommendation: string
}

export interface ScalabilityBottleneck {
  title: string
  risk: 'critical' | 'high' | 'medium' | 'low'
  area: 'database' | 'api' | 'memory' | 'storage' | 'concurrency' | 'architecture'
  explanation: string
  impact: string
  recommendation: string
  file: string
  line: number | null
}

export interface ScalabilityAssessment {
  scalabilityScore: number
  summary: string
  bottlenecks: ScalabilityBottleneck[]
}

export interface AnalysisResult {
  securityScore: number
  summary: string
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: AIFinding[]
  complianceIssues?: ComplianceIssue[]
  suppressedCount?: number
  scalability?: ScalabilityAssessment
}

export interface SuppressedFinding {
  key: string
  title: string
  file: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  date: string
}

export interface FixPatch {
  file: string
  search: string
  replace: string
  explanation: string
}

export interface ApplyFixResult {
  backupId: string
}

export interface OsvFinding {
  package: string
  version: string
  ecosystem: string
  ids: string[]
  aliases: string[]
  cvss: number | null
  summary: string
  fixedVersion: string | null
  file: string
}

export interface ScanComparison {
  fixedCount: number
  newCount: number
  unchangedCount: number
  scoreDelta: number
  prevScore: number
  prevDate: string
}

export interface ScanResult {
  semgrepFindings: SemgrepFinding[]
  gitleaksFindings: GitleaksFinding[]
  osvFindings: OsvFinding[]
  error: string | null
  cancelled?: boolean
  analysis?: AnalysisResult
  analysisError?: string
  comparison?: ScanComparison
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

export interface ScanHistoryEntry {
  id: string
  date: string           // ISO string
  folderPath: string
  folderName: string
  securityScore: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: AIFinding[]
  summary: string
  scalability?: ScalabilityAssessment
}

// ---------------------------------------------------------------------------
// License types
// ---------------------------------------------------------------------------

export interface LicenseValidateResult {
  valid: boolean
  customerEmail: string
  error: string | null
}

export interface AuthSessionInfo {
  signedIn: boolean
  email: string | null
  licensed: boolean
  plan: string | null
}

export interface AiProviderInfo {
  provider: string
  model: string
  baseUrl: string
  configured: boolean
  needsKey: boolean
  providers: Array<{ id: string; label: string; needsKey: boolean; defaultModel: string; keyUrl: string }>
}

export interface LicenseStatus {
  activated: boolean
  email: string | null
  keyMasked: string | null
}

// ---------------------------------------------------------------------------
// Window augmentation
// ---------------------------------------------------------------------------

declare global {
  interface Window {
    electron: ElectronAPI
    api: {
      // Folder
      selectFolder: () => Promise<string | null>
      getFolderStats: (folderPath: string) => Promise<FolderStats>
      // Scan
      runScan: (folderPath: string) => Promise<ScanResult>
      cancelScan: () => Promise<void>
      onScanProgress: (callback: (progress: ScanProgress) => void) => () => void
      // AI
      saveApiKey: (key: string) => Promise<void>
      getApiKeyStatus: () => Promise<boolean>
      getAiProvider: () => Promise<AiProviderInfo>
      setAiProvider: (settings: { provider: string; model?: string; baseUrl?: string }) => Promise<void>
      testAiProvider: () => Promise<{ ok: boolean; detail: string }>
      detectProviderFromKey: (key: string) => Promise<string | null>
      analyzeFindings: (semgrepFindings: unknown[], gitleaksFindings: unknown[], osvFindings?: unknown[]) => Promise<AnalysisResult>
      generateFix: (folderPath: string, finding: AIFinding) => Promise<FixPatch>
      applyFix: (folderPath: string, patch: FixPatch) => Promise<ApplyFixResult>
      revertFix: (backupId: string) => Promise<void>
      suppressFinding: (folderPath: string, finding: AIFinding) => Promise<SuppressedFinding[]>
      unsuppressFinding: (folderPath: string, key: string) => Promise<SuppressedFinding[]>
      getSuppressions: (folderPath: string) => Promise<SuppressedFinding[]>
      getHookStatus: (folderPath: string) => Promise<boolean>
      installHook: (folderPath: string, minScore: number) => Promise<void>
      uninstallHook: (folderPath: string) => Promise<void>
      // License
      validateLicense: (key: string) => Promise<LicenseValidateResult>
      getLicenseStatus: () => Promise<LicenseStatus>
      authAvailable: () => Promise<boolean>
      authSignUp: (email: string, password: string) => Promise<AuthSessionInfo>
      authSignIn: (email: string, password: string) => Promise<AuthSessionInfo>
      authSignOut: () => Promise<void>
      authGetSession: () => Promise<AuthSessionInfo>
      getMachineId: () => Promise<string>
      deactivateLicense: () => Promise<void>
      // History
      getScanHistory: () => Promise<ScanHistoryEntry[]>
      getScanById: (id: string) => Promise<ScanHistoryEntry | null>
      deleteScan: (id: string) => Promise<void>
      savePdfReport: (filename: string, data: Uint8Array) => Promise<string>
      getAppVersion: () => Promise<string>
      onNavigateTo: (callback: (page: string) => void) => () => void
    }
  }
}
