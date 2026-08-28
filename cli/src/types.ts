export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface AIFinding {
  id: string
  title: string
  severity: Severity
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
  risk: Severity
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

export interface SemgrepFinding {
  check_id: string
  path: string
  start?: { line?: number }
  extra?: {
    message?: string
    severity?: string
    metadata?: { cwe?: string[]; owasp?: string[] }
  }
}

export interface GitleaksFinding {
  Description: string
  File: string
  StartLine: number
  Secret: string
  RuleID: string
}

/** A scanner either produced results or failed — never conflate failure with "clean". */
export interface ScannerOutcome<T> {
  ok: boolean
  findings: T[]
  error: string | null
  skipped: boolean
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
  folderPath: string
  date: string
  code: ScannerOutcome<SemgrepFinding>
  secrets: ScannerOutcome<GitleaksFinding>
  deps: ScannerOutcome<OsvFinding>
  score: number
  scoreSource: 'ai' | 'heuristic'
  analysis: AnalysisResult | null
  analysisError: string | null
  comparison?: ScanComparison
}

export interface SuppressedFinding {
  key: string
  title: string
  file: string
  severity: Severity
  date: string
}

export interface HistoryEntry {
  id: string
  date: string
  folderPath: string
  folderName: string
  securityScore: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  summary: string
}

export interface FixPatch {
  file: string
  search: string
  replace: string
  explanation: string
}
